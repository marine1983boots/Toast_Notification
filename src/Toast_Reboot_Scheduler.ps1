<#
.SYNOPSIS
Schedules system reboot for BIOS update (Stage 4 enforcement)

.DESCRIPTION
This script is invoked when a user clicks "Schedule Reboot" after exhausting
all 4 snooze attempts. It calculates an appropriate maintenance window time
(tonight 8 PM or tomorrow 6 AM) and creates a scheduled task to initiate shutdown.

.PARAMETER ToastGUID
Unique identifier for this toast notification instance

.EXAMPLE
.\Toast_Reboot_Scheduler.ps1 -ToastGUID "ABC123..."
#>

Param(
    [Parameter(Mandatory=$true)]
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
        Set-ItemProperty -Path $RegPath -Name "ScheduledRebootTime" -Value $RebootTime.ToString('s') -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegPath -Name "RebootScheduledBy" -Value $env:USERNAME -ErrorAction SilentlyContinue
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
    Register-ScheduledTask -TaskName $TaskName -InputObject $New_Task -Force | Out-Null

    Write-Output "Reboot task created successfully: $TaskName"

    # Verify task was created
    $VerifyTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($VerifyTask) {
        Write-Output "Task verification: SUCCESS"
        Write-Output "Reboot scheduled for: $($RebootTime.ToString('g'))"
    }
    else {
        Write-Error "Task verification: FAILED - Task not found after registration"
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
