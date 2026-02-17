<#
.SYNOPSIS
    Handles toast-reboot:// protocol for immediate system reboot (Stage 4)

.DESCRIPTION
    This script is invoked when user clicks "Reboot Now" button in Stage 4 toast.
    Cancels any pending shutdown countdown and initiates immediate reboot (10 second warning).
    When invoked from a -Snooze toast, also cleans up registry state and scheduled tasks
    for this toast GUID before rebooting.

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

                # 1. Remove registry state for this toast GUID
                $RegKeyPath = "${RegistryHive}:\${RegistryPath}\$ToastGUID"
                try {
                    if (Test-Path $RegKeyPath) {
                        Remove-Item -Path $RegKeyPath -Recurse -Force -ErrorAction Stop
                        Write-Output "[OK] Registry state removed: $RegKeyPath"
                    }
                    else {
                        Write-Output "[INFO] Registry key not found (already removed or not created): $RegKeyPath"
                    }
                }
                catch {
                    Write-Warning "Could not remove registry key: $($_.Exception.Message)"
                    Write-Warning "Continuing with reboot - registry cleanup non-fatal"
                }

                # 2. Disable all pre-created snooze tasks for this GUID
                for ($i = 1; $i -le 4; $i++) {
                    $TaskName = "Toast_Notification_$($ToastGUID)_Snooze$i"
                    try {
                        $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                        if ($Task) {
                            if ($Task.State -ne 'Disabled') {
                                Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
                                Write-Output "[OK] Snooze task disabled: $TaskName"
                            }
                            else {
                                Write-Output "[INFO] Snooze task already disabled: $TaskName"
                            }
                        }
                        else {
                            Write-Output "[INFO] Snooze task not found (may not have been pre-created): $TaskName"
                        }
                    }
                    catch {
                        Write-Warning "Could not disable task ${TaskName}: $($_.Exception.Message)"
                        Write-Warning "Continuing with reboot - task cleanup non-fatal"
                    }
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
