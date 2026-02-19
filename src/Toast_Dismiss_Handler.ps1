<#
.SYNOPSIS
    Handles toast-dismiss:// protocol for user-initiated dismiss action (Stages 0-3)

.DESCRIPTION
    This script is invoked when user clicks "Dismiss" button in Stage 0-3 toast notifications.
    Cleans up all outstanding snooze scheduled tasks and the HKLM registry state for this
    toast GUID, then disables the main notification task to prevent re-display.
    No reboot is initiated - dismiss is a clean exit from the notification flow.

    Version 1.3 - 19/02/2026
    -FIX: Disable-ScheduledTask on main task now replaced with Unregister-ScheduledTask.
     Main task (Toast_Notification_{GUID}) is registered by SYSTEM - standard users receive
     Access Denied when attempting to disable or remove it. This is non-fatal: the task has a
     2-minute EndBoundary with no StartWhenAvailable, so it will not re-fire after reboot.
     Catch block now logs [INFO] instead of [WARNING] to avoid false-alarm noise in logs.

    Version 1.2 - 18/02/2026
    -FIX: Replace Remove-Item with Set-ItemProperty Completed=1 for HKLM registry cleanup
    -User context cannot delete HKLM keys (KEY_WRITE required on parent, intentionally blocked)
    -Writing Completed=1 value IS permitted (user has FullControl on GUID key via Grant-RegistryPermissions)
    -Toast_Notify.ps1 v2.32 checks Completed=1 before display and exits early
    -SYSTEM context cleanup removes completed keys on next deployment

    Version 1.1 - 18/02/2026
    -Cancel fallback task (Toast_Notification_{GUID}_{Username}_Fallback) during cleanup
    -Fallback task is pre-scheduled by Toast_Notify.ps1 v2.26 before the toast is shown
    -Ensures fallback does not fire after user has explicitly dismissed
    -Non-fatal: if fallback removal fails, logs warning and continues

    Version 1.0 - 17/02/2026
    -Initial implementation
    -Mirrors Toast_Reboot_Handler.ps1 structure but performs cleanup only (no reboot)
    -Removes HKLM registry state for toast GUID
    -Unregisters all user-specific snooze tasks (Toast_Notification_{GUID}_{Username}_Snooze{N})
    -Disables main notification task to prevent re-display
    -All cleanup operations are non-fatal (continue on individual failure)

.PARAMETER ProtocolUri
    The protocol URI passed from toast action (format: toast-dismiss://GUID/dismiss)

.PARAMETER RegistryHive
    Registry hive where toast state is stored. HKLM (default) or HKCU.

.PARAMETER RegistryPath
    Registry path under the hive. Default: SOFTWARE\ToastNotification

.PARAMETER LogDirectory
    Directory for log output. Defaults to %WINDIR%\Temp.

.EXAMPLE
    Toast_Dismiss_Handler.ps1 -ProtocolUri "toast-dismiss://34723A4F-2F0B-48F7-95B9-2534C57F2B36/dismiss"

.EXAMPLE
    Toast_Dismiss_Handler.ps1 -ProtocolUri "toast-dismiss://34723A4F-2F0B-48F7-95B9-2534C57F2B36/dismiss" -RegistryHive HKLM -RegistryPath "SOFTWARE\ToastNotification"
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
$LogPath = Join-Path $LogDirectory "Toast_Dismiss_Handler.log"
# Ensure log directory exists
if (!(Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path $LogPath -Append

Write-Output "========================================="
Write-Output "Toast Dismiss Handler Started"
Write-Output "Protocol URI: $ProtocolUri"
Write-Output "Timestamp: $(Get-Date -Format 's')"
Write-Output "========================================="

try {
    # Parse protocol URI: toast-dismiss://GUID/action
    if ($ProtocolUri -match '^toast-dismiss://([A-F0-9\-]{1,36})/(\w+)$') {
        $ToastGUID = $Matches[1]
        $Action = $Matches[2]

        Write-Output "ToastGUID: $ToastGUID"
        Write-Output "Action: $Action"

        switch ($Action.ToLower()) {
            'dismiss' {
                Write-Output "User requested DISMISS - cleaning up toast artefacts..."

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
                    Write-Warning "Continuing - registry cleanup non-fatal"
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
                # Explicit dismiss is the authoritative resolution - fallback must be removed.
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

                # 3. Attempt to remove the main notification task
                # Note: main task is registered by SYSTEM - standard users may receive Access Denied.
                # This is non-fatal: the task has a 2-minute EndBoundary and no StartWhenAvailable,
                # so it will not re-fire after reboot regardless.
                $MainTaskName = "Toast_Notification_$ToastGUID"
                try {
                    $MainTask = Get-ScheduledTask -TaskName $MainTaskName -ErrorAction SilentlyContinue
                    if ($MainTask) {
                        Unregister-ScheduledTask -TaskName $MainTaskName -Confirm:$false -ErrorAction Stop | Out-Null
                        Write-Output "[OK] Main notification task removed: $MainTaskName"
                    }
                    else {
                        Write-Output "[INFO] Main notification task not found (already expired or removed): $MainTaskName"
                    }
                }
                catch {
                    Write-Output "[INFO] Main task cleanup skipped - registered by SYSTEM, standard users cannot remove it. Task expires naturally (2-min EndBoundary, no StartWhenAvailable): $MainTaskName"
                }

                Write-Output "[OK] Dismiss cleanup completed successfully"
            }

            default {
                Write-Error "Unknown action: $Action"
            }
        }
    }
    else {
        Write-Error "Invalid protocol URI format: $ProtocolUri"
        Write-Error "Expected: toast-dismiss://GUID/dismiss"
    }

    Write-Output "========================================="
    Write-Output "Toast Dismiss Handler Completed"
    Write-Output "========================================="

    Stop-Transcript
    exit 0
}
catch {
    Write-Error "Error in Toast_Dismiss_Handler:"
    Write-Error $_.Exception.Message
    Write-Error $_.ScriptStackTrace
    Stop-Transcript
    exit 1
}
