<#
===========================================================================
Created on:   12/02/2026
Created by:   Ben Whitmore (with AI assistance)
Filename:     Toast_Reboot_Scheduler.ps1
===========================================================================

Version 1.1 - 16/02/2026
-Added [CmdletBinding()] for proper cmdlet behavior
-Added ValidatePattern to ToastGUID parameter for input validation
-Fixed ErrorActionPreference contradiction (removed SilentlyContinue from registry operations)
-Added comprehensive error handling with try-catch for registry operations
-Added task verification after Register-ScheduledTask

Version 1.0 - 12/02/2026
-Initial release
-Schedules system reboot for BIOS update (Stage 4 enforcement)
-Calculates maintenance window time (tonight 8 PM or tomorrow 6 AM)
-Creates scheduled task to initiate shutdown with 5-minute warning

.SYNOPSIS
    Schedules system reboot for BIOS update (Stage 4 enforcement)

.DESCRIPTION
    This script is invoked when a user clicks "Schedule Reboot" after exhausting
    all 4 snooze attempts. It calculates an appropriate maintenance window time
    (tonight 8 PM or tomorrow 6 AM) and creates a scheduled task to initiate shutdown.

    The script runs in USER context when invoked via toast-reboot:// protocol handler
    but creates a scheduled task running as SYSTEM to perform the actual shutdown.

.PARAMETER ToastGUID
    Unique identifier for this toast notification instance.
    Format: Uppercase alphanumeric with hyphens (e.g., ABC-123-DEF)

.EXAMPLE
    Toast_Reboot_Scheduler.ps1 -ToastGUID "ABC-123-DEF"

    Schedules a system reboot for the specified toast notification GUID.
    If current time is before 5 PM, schedules for 8 PM today.
    If current time is after 5 PM, schedules for 6 AM tomorrow.

.NOTES
    Author: Ben Whitmore
    Version: 1.1
    Last Modified: 16/02/2026

    This script requires:
    - Write access to HKLM:\SOFTWARE\ToastNotification\BIOS_Updates\{GUID} registry path
    - Permission to create scheduled tasks

    Initial deployment should run as SYSTEM to ensure proper permissions.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[A-F0-9\-]{1,36}$')]
    [String]$ToastGUID
)

# Start logging
$LogPath = (Join-Path $ENV:Windir "Temp\$($ToastGuid)_Reboot.log")
Start-Transcript -Path $LogPath -Append

Write-Output "========================================="
Write-Output "Toast Reboot Scheduler Started"
Write-Output "ToastGUID: $ToastGUID"
Write-Output "Timestamp: $(Get-Date -Format 's')"
Write-Output "========================================="

# Registry path for this toast instance
$RegPath = "HKLM:\SOFTWARE\ToastNotification\BIOS_Updates\$ToastGUID"

try {
    $ErrorActionPreference = 'Stop'

    # Determine reboot time based on current time
    $Now = Get-Date
    $Hour = $Now.Hour
    $RebootTime = $null
    $RebootDescription = ""

    if ($Hour -lt 17) {
        # Before 5 PM - schedule for 8 PM today
        $RebootTime = Get-Date -Hour 20 -Minute 0 -Second 0
        $RebootDescription = "Tonight at 8:00 PM"
        Write-Output "Scheduling reboot for tonight at 8:00 PM"
    }
    else {
        # After 5 PM - schedule for 6 AM tomorrow
        $RebootTime = (Get-Date).AddDays(1)
        $RebootTime = Get-Date -Date $RebootTime -Hour 6 -Minute 0 -Second 0
        $RebootDescription = "Tomorrow at 6:00 AM"
        Write-Output "Scheduling reboot for tomorrow at 6:00 AM"
    }

    Write-Output "Reboot scheduled for: $($RebootTime.ToString('s'))"

    # Update registry with scheduled reboot time
    if (Test-Path $RegPath) {
        Write-Output "Updating registry with scheduled reboot time..."
        try {
            Set-ItemProperty -Path $RegPath -Name "ScheduledRebootTime" -Value $RebootTime.ToString('s') -ErrorAction Stop
            Set-ItemProperty -Path $RegPath -Name "RebootScheduledBy" -Value $env:USERNAME -ErrorAction Stop
        }
        catch [System.UnauthorizedAccessException] {
            Write-Warning "========================================"
            Write-Warning "ACCESS DENIED - Registry Write Failed"
            Write-Warning "========================================"
            Write-Warning ""
            Write-Warning "Unable to write scheduled reboot time to registry."
            Write-Warning "The reboot task will still be created, but tracking information will be limited."
            Write-Warning ""
            Write-Warning "To fix permanently:"
            Write-Warning "1. Deploy Toast_Notify.ps1 as SYSTEM with -EnableProgressive"
            Write-Warning "2. Or use -RegistryHive HKCU for per-user state"
            Write-Warning ""
            Write-Warning "Registry Path: $RegPath"
            Write-Warning "========================================"
            # Continue execution - registry write is not critical for reboot task
        }
        catch {
            Write-Warning "Failed to update registry: $($_.Exception.Message)"
            # Continue execution - registry write is not critical for reboot task
        }
    }

    # Create scheduled task for reboot
    Write-Output "Creating scheduled task for system reboot..."
    $TaskName = "BIOS_Reboot_$ToastGUID"

    # Remove old task if it exists
    $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($ExistingTask) {
        Write-Output "Removing existing reboot task: $TaskName"
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    # Build shutdown command (5 minute warning)
    $ShutdownCommand = "shutdown.exe"
    $ShutdownArgs = "/r /t 300 /c `"BIOS Update: Your system will restart in 5 minutes for a critical security update. Please save your work now.`" /d p:2:17"

    # Create task action
    $Task_Action = New-ScheduledTaskAction `
        -Execute $ShutdownCommand `
        -Argument $ShutdownArgs

    # Create trigger for calculated reboot time
    $Task_Trigger = New-ScheduledTaskTrigger -Once -At $RebootTime

    # Create principal (SYSTEM - required for shutdown)
    $Task_Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Create settings
    $Task_Settings = New-ScheduledTaskSettingsSet `
        -Compatibility Win8 `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -WakeToRun

    # Build task
    $New_Task = New-ScheduledTask `
        -Description "BIOS Update Reboot - Scheduled for $($RebootTime.ToString('g')). User: $env:USERNAME. 5-minute warning before shutdown." `
        -Action $Task_Action `
        -Principal $Task_Principal `
        -Trigger $Task_Trigger `
        -Settings $Task_Settings

    # Register task
    try {
        Register-ScheduledTask -TaskName $TaskName -InputObject $New_Task -Force -ErrorAction Stop | Out-Null
    }
    catch [System.UnauthorizedAccessException] {
        Write-Error "========================================"
        Write-Error "ACCESS DENIED - Scheduled Task Registration Failed"
        Write-Error "========================================"
        Write-Error ""
        Write-Error "This error indicates insufficient permissions to register scheduled tasks."
        Write-Error ""
        Write-Error "SOLUTIONS:"
        Write-Error "1. Initial deployment should run as SYSTEM to register protocol handler"
        Write-Error "   This grants necessary permissions for subsequent USER context invocations"
        Write-Error ""
        Write-Error "2. If deployed correctly, check Group Policy restrictions:"
        Write-Error "   - Computer Configuration > Windows Settings > Security Settings"
        Write-Error "   - Local Policies > User Rights Assignment > Create scheduled tasks"
        Write-Error "   - Verify BUILTIN\Users has this right"
        Write-Error ""
        Write-Error "3. Alternative: Use current user principal (if supported by your environment):"
        Write-Error "   Modify line 91 to:"
        Write-Error "   `$Task_Principal = New-ScheduledTaskPrincipal -UserId `$env:USERNAME -RunLevel Limited"
        Write-Error "   NOTE: This may prevent system shutdown (requires SYSTEM or admin rights)"
        Write-Error ""
        Write-Error "4. Manual permission grant (PowerShell as Admin):"
        Write-Error "   schtasks /create /tn ""$TaskName"" /tr ""shutdown.exe"" /sc once /st 00:00 /ru SYSTEM"
        Write-Error ""
        Write-Error "Task Name: $TaskName"
        Write-Error "Current User: $env:USERNAME"
        Write-Error "Current Context: USER (not SYSTEM)"
        Write-Error "========================================"
        Stop-Transcript
        exit 1
    }
    catch {
        Write-Error "Failed to register scheduled task: $($_.Exception.Message)"
        Write-Error "Task Name: $TaskName"
        Write-Error "Error Type: $($_.Exception.GetType().FullName)"
        Stop-Transcript
        exit 1
    }

    Write-Output "Reboot task created successfully: $TaskName"

    # Verify task was created
    $VerifyTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($VerifyTask) {
        Write-Output "Task verification: [OK]"
        Write-Output "Reboot scheduled for: $($RebootTime.ToString('g'))"
    }
    else {
        Write-Error "Task verification: [FAIL] - Task not found after registration"
    }

    # Display confirmation toast
    Write-Output "Displaying confirmation toast..."

    # Load Windows Runtime assemblies
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    # Build confirmation toast XML
    $ConfirmationXML = @"
<toast duration="long" scenario="reminder">
    <visual>
        <binding template="ToastGeneric">
            <text>[SUCCESS] Reboot Scheduled Successfully</text>
            <text>Your system will restart $RebootDescription</text>
            <text placement="attribution">BIOS Update - Compliance Scheduled</text>
            <group>
                <subgroup>
                    <text hint-style="body" hint-wrap="true">You will receive a 5-minute warning before the restart. Please ensure your work is saved before this time.</text>
                </subgroup>
            </group>
            <group>
                <subgroup>
                    <text hint-style="captionSubtle">To cancel or reschedule, contact IT Support</text>
                </subgroup>
            </group>
        </binding>
    </visual>
    <audio src="ms-winsoundevent:notification.default"/>
</toast>
"@

    # Prepare and display confirmation toast
    $ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
    $ToastXml.LoadXml($ConfirmationXML)
    $ToastMessage = [Windows.UI.Notifications.ToastNotification]::New($ToastXML)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("MSEdge").Show($ToastMessage)

    Write-Output "Confirmation toast displayed"

    Write-Output "========================================="
    Write-Output "Toast Reboot Scheduler Completed Successfully"
    Write-Output "Reboot Time: $($RebootTime.ToString('s'))"
    Write-Output "========================================="

    Stop-Transcript
    exit 0
}
catch {
    Write-Error "An error occurred in Toast_Reboot_Scheduler:"
    Write-Error $_.Exception.Message
    Write-Error $_.ScriptStackTrace
    Stop-Transcript
    exit 1
}
