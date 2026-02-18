<#
.SYNOPSIS
    Handles toast-reboot:// protocol for immediate system reboot (Stage 4)

.DESCRIPTION
    This script is invoked when user clicks "Reboot Now" button in Stage 4 toast.
    Cancels any pending shutdown countdown and initiates immediate reboot (10 second warning).
    When invoked from a -Snooze toast, also cleans up registry state and scheduled tasks
    for this toast GUID before rebooting.

    Version 1.4 - 18/02/2026
    -FIX: Replace Remove-Item with Set-ItemProperty Completed=1 for HKLM registry cleanup
    -User context cannot delete HKLM keys (KEY_WRITE required on parent, intentionally blocked)
    -Writing Completed=1 value IS permitted (user has FullControl on GUID key via Grant-RegistryPermissions)
    -Toast_Notify.ps1 v2.32 checks Completed=1 before display and exits early
    -SYSTEM context cleanup removes completed keys on next deployment

    Version 1.3 - 18/02/2026
    -Cancel fallback task (Toast_Notification_{GUID}_{Username}_Fallback) during cleanup
    -Fallback task is pre-scheduled by Toast_Notify.ps1 v2.26 before the toast is shown
    -Ensures fallback does not fire after reboot path is taken
    -Non-fatal: if fallback removal fails, logs warning and continues

    Version 1.2 - 17/02/2026
    -FIX: Task cleanup now uses username-qualified names matching v1.9 snooze handler format
    -FIX: Use Unregister-ScheduledTask instead of Disable-ScheduledTask (fully removes tasks)
    -FIX: Added cleanup of main Toast_Notification_{GUID} task to prevent re-display after reboot
    -Loop extended to 10 snooze iterations (was 4, breaks early if no more tasks found)

    Version 1.1 - 17/02/2026
    -Added registry cleanup before reboot: removes GUID registry key (clears snooze state)
    -Added scheduled task cleanup: disables all 4 pre-created snooze tasks for this GUID
    -Added -RegistryHive and -RegistryPath parameters for registry location targeting
    -Reboot Now from any stage (0-4) now cleanly removes all toast artefacts before rebooting

.PARAMETER ProtocolUri
    The protocol URI passed from toast action (format: toast-reboot://GUID/immediate)

.PARAMETER RegistryHive
    Registry hive where toast state is stored. HKLM (default) or HKCU.

.PARAMETER RegistryPath
    Registry path under the hive. Default: SOFTWARE\ToastNotification

.PARAMETER LogDirectory
    Directory for log output. Defaults to %WINDIR%\Temp.

.EXAMPLE
    Toast_Reboot_Handler.ps1 -ProtocolUri "toast-reboot://ABC-123/immediate"

.EXAMPLE
    Toast_Reboot_Handler.ps1 -ProtocolUri "toast-reboot://ABC-123/immediate" -RegistryHive HKLM -RegistryPath "SOFTWARE\ToastNotification"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [String]$ProtocolUri,
    [Parameter(Mandatory = $false)]
    [ValidateSet('HKLM', 'HKCU')]
    [String]$RegistryHive = 'HKLM',
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-zA-Z0-9_\\]+$')]
    [String]$RegistryPath = 'SOFTWARE\ToastNotification',
    [Parameter(Mandatory = $false)]
    [String]$LogDirectory = $ENV:WINDIR + "\Temp"
)

# Start logging
$LogPath = Join-Path $LogDirectory "Toast_Reboot_Handler.log"
# Ensure log directory exists
if (!(Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path $LogPath -Append

Write-Output "========================================="
Write-Output "Toast Reboot Handler Started"
Write-Output "Protocol URI: $ProtocolUri"
Write-Output "Timestamp: $(Get-Date -Format 's')"
Write-Output "========================================="

try {
    # Parse protocol URI: toast-reboot://GUID/action
    if ($ProtocolUri -match '^toast-reboot://([A-F0-9\-]{1,36})/(\w+)$') {
        $ToastGUID = $Matches[1]
        $Action = $Matches[2]

        Write-Output "ToastGUID: $ToastGUID"
        Write-Output "Action: $Action"

        switch ($Action.ToLower()) {
            'immediate' {
                Write-Output "User requested IMMEDIATE REBOOT"

                Write-Output "Cleaning up toast registry state and scheduled tasks..."

                # 1. Mark registry state as Completed=1
                # Cannot delete HKLM key from user context (requires KEY_WRITE on parent, which is intentionally blocked).
                # Writing a value to the key IS permitted (user has FullControl on GUID key via Grant-RegistryPermissions).
                # Toast_Notify.ps1 checks Completed=1 before display and exits early. SYSTEM context cleanup removes
                # orphaned Completed keys on next deployment.
                $RegKeyPath = "${RegistryHive}:\${RegistryPath}\$ToastGUID"
                try {
                    if (Test-Path $RegKeyPath) {
                        Set-ItemProperty -Path $RegKeyPath -Name "Completed" -Value 1 -Type DWord -Force -ErrorAction Stop
                        Write-Output "[OK] Registry state marked Completed=1: $RegKeyPath"
                    }
                    else {
                        Write-Output "[INFO] Registry key not found (already removed or not created): $RegKeyPath"
                    }
                }
                catch {
                    Write-Warning "Could not mark registry key as completed: $($_.Exception.Message)"
                    Write-Warning "Continuing with reboot - registry cleanup non-fatal"
                }

                # 2. Unregister all user-specific snooze tasks for this GUID
                # v1.9+: task names include username to deconflict multi-user endpoints
                # Format: Toast_Notification_{GUID}_{Username}_Snooze{N}
                $CleanupUsername = $env:USERNAME
                for ($i = 1; $i -le 10; $i++) {
                    $TaskName = "Toast_Notification_${ToastGUID}_${CleanupUsername}_Snooze${i}"
                    try {
                        $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                        if ($Task) {
                            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
                            Write-Output "[OK] Snooze task removed: $TaskName"
                        }
                        else {
                            # No more tasks at this index - stop looking
                            if ($i -gt 1) { break }
                        }
                    }
                    catch {
                        Write-Warning "Could not remove task ${TaskName}: $($_.Exception.Message)"
                        Write-Warning "Continuing - task cleanup non-fatal"
                    }
                }

                # 2b. Cancel fallback task (pre-scheduled by Toast_Notify.ps1 v2.26)
                # Fallback fires if user ignores toast (Learn More, timeout, natural dismiss).
                # Reboot path is the authoritative resolution - fallback must be removed.
                $FallbackTaskName = "Toast_Notification_${ToastGUID}_${CleanupUsername}_Fallback"
                try {
                    $FallbackTask = Get-ScheduledTask -TaskName $FallbackTaskName -ErrorAction SilentlyContinue
                    if ($FallbackTask) {
                        Unregister-ScheduledTask -TaskName $FallbackTaskName -Confirm:$false -ErrorAction Stop
                        Write-Output "[OK] Fallback task removed: $FallbackTaskName"
                    }
                    else {
                        Write-Output "[INFO] No fallback task found: $FallbackTaskName"
                    }
                }
                catch {
                    Write-Warning "[!] Fallback task removal non-fatal: $($_.Exception.Message)"
                }

                # 3. Disable the main notification task to prevent re-display after reboot
                # Without this, Toast_Notification_{GUID} fires again after restart
                $MainTaskName = "Toast_Notification_$ToastGUID"
                try {
                    $MainTask = Get-ScheduledTask -TaskName $MainTaskName -ErrorAction SilentlyContinue
                    if ($MainTask) {
                        Disable-ScheduledTask -TaskName $MainTaskName -ErrorAction Stop | Out-Null
                        Write-Output "[OK] Main notification task disabled: $MainTaskName"
                    }
                    else {
                        Write-Output "[INFO] Main notification task not found: $MainTaskName"
                    }
                }
                catch {
                    Write-Warning "Could not disable main task ${MainTaskName}: $($_.Exception.Message)"
                    Write-Warning "Continuing - task cleanup non-fatal"
                }

                Write-Output "[OK] Cleanup completed - proceeding with reboot"
                Write-Output "Cancelling any pending shutdown countdown..."

                # Cancel any existing shutdown
                $CancelResult = & shutdown.exe /a 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Output "[OK] Cancelled pending shutdown"
                }
                else {
                    Write-Output "[INFO] No pending shutdown to cancel (this is normal)"
                }

                # Initiate immediate reboot (10 second warning)
                Write-Output "Initiating reboot in 10 seconds..."
                $RebootCommand = "shutdown.exe /r /t 10 /c `"BIOS Update: Reboot initiated by user. System will restart in 10 seconds. Save your work now!`" /d p:2:18"
                Write-Output "Executing: $RebootCommand"

                Invoke-Expression $RebootCommand

                Write-Output "[OK] Immediate reboot initiated successfully"
            }

            'schedule' {
                Write-Output "User requested SCHEDULED REBOOT"
                Write-Output "Calling Toast_Reboot_Scheduler.ps1..."

                $SchedulerPath = Join-Path $PSScriptRoot "Toast_Reboot_Scheduler.ps1"
                if (Test-Path $SchedulerPath) {
                    & $SchedulerPath -ToastGUID $ToastGUID
                    Write-Output "[OK] Reboot scheduler completed"
                }
                else {
                    Write-Error "Toast_Reboot_Scheduler.ps1 not found: $SchedulerPath"
                }
            }

            default {
                Write-Error "Unknown action: $Action"
            }
        }
    }
    else {
        Write-Error "Invalid protocol URI format: $ProtocolUri"
        Write-Error "Expected: toast-reboot://GUID/action"
    }

    Write-Output "========================================="
    Write-Output "Toast Reboot Handler Completed"
    Write-Output "========================================="

    Stop-Transcript
    exit 0
}
catch {
    Write-Error "Error in Toast_Reboot_Handler:"
    Write-Error $_.Exception.Message
    Write-Error $_.ScriptStackTrace
    Stop-Transcript
    exit 1
}
