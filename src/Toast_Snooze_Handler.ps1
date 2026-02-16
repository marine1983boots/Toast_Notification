<#
===========================================================================
Created on:   12/02/2026
Created by:   Ben Whitmore (with AI assistance)
Filename:     Toast_Snooze_Handler.ps1
===========================================================================

Version 1.2 - 16/02/2026
-Added configurable registry location: $RegistryHive and $RegistryPath parameters
-Added $LogDirectory parameter for centralized logging
-Added comprehensive UnauthorizedAccessException error handling with solution guidance
-Dynamic registry path construction based on deployment configuration
-Fixes Access Denied errors in corporate environments

Version 1.1 - 12/02/2026
-Applied [System.Uri] class for proper protocol URI parsing
-Added post-decode validation to prevent bypass attacks
-Enhanced error messages with context
-Added fragment and query string rejection

Version 1.0 - 12/02/2026
-Initial release
-Handles toast-snooze:// protocol URIs
-Parses URI to extract ToastGUID and SnoozeInterval
-Reads current SnoozeCount from registry
-Increments SnoozeCount (max 4)
-Updates registry with new count and timestamps
-Calculates trigger time based on interval
-Creates scheduled task for next stage with incremented count

.SYNOPSIS
Handles progressive toast snooze protocol URIs

.DESCRIPTION
This script is registered as the handler for the toast-snooze:// custom protocol.
When a user clicks a snooze button in a progressive toast notification, Windows
invokes this script with the protocol URI as a parameter.

The script parses the URI, increments the snooze counter in the registry,
and schedules the next toast notification with the appropriate stage level.

Protocol URI format: toast-snooze://GUID/INTERVAL
- GUID: ToastGUID (uppercase, hyphenated)
- INTERVAL: One of 15m, 30m, 1h, 2h, 4h, eod

.PARAMETER ProtocolUri
The full protocol URI passed by Windows when the protocol is invoked.
Format: toast-snooze://GUID/INTERVAL

.EXAMPLE
Toast_Snooze_Handler.ps1 -ProtocolUri "toast-snooze://ABC-123-DEF/2h"
Processes a 2-hour snooze request for toast GUID ABC-123-DEF

.NOTES
This script must be executed with sufficient permissions to:
- Read/write HKLM:\SOFTWARE\ToastNotification\* registry keys
- Create scheduled tasks in Task Scheduler

The script is typically registered in the SYSTEM context during initial
Toast_Notify.ps1 deployment but executes in USER context when invoked.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^toast-snooze://[A-F0-9\-]{1,36}/(15m|30m|1h|2h|4h|eod)$')]
    [String]$ProtocolUri,
    [Parameter(Mandatory = $false)]
    [ValidateSet('HKLM', 'HKCU')]
    [String]$RegistryHive = 'HKLM',
    [Parameter(Mandatory = $false)]
    [String]$RegistryPath = 'SOFTWARE\ToastNotification',
    [Parameter(Mandatory = $false)]
    [String]$LogDirectory = $ENV:Windir + "\Temp"
)

#region Helper Functions

function Parse-SnoozeUri {
    <#
    .SYNOPSIS
        Parses toast-snooze:// protocol URI using [System.Uri] for proper decoding
    .PARAMETER Uri
        Protocol URI to parse
    .EXAMPLE
        Parse-SnoozeUri -Uri "toast-snooze://ABC-123-DEF/2h"
        Returns: @{ToastGUID='ABC-123-DEF'; Interval='2h'}
    .NOTES
        Uses [System.Uri] class for proper URL decoding and component extraction.
        Validates both encoded and decoded forms to prevent bypass attacks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$Uri
    )

    try {
        Write-Verbose "Parsing URI: $Uri"

        # Create [System.Uri] object for proper URI parsing
        $UriObject = New-Object System.Uri($Uri)

        # Verify scheme is correct
        if ($UriObject.Scheme -ne 'toast-snooze') {
            throw "Invalid URI scheme: Expected 'toast-snooze', got '$($UriObject.Scheme)'"
        }

        # Extract host (ToastGUID) - properly decoded
        # NOTE: [System.Uri].Host automatically lowercases, so we extract from Authority and UserInfo
        $ToastGUID = $UriObject.Host
        if ([string]::IsNullOrWhiteSpace($ToastGUID)) {
            throw "URI missing host component (ToastGUID)"
        }

        # Check if URI contains @ (user info separator) which would indicate malformed GUID
        if (![string]::IsNullOrWhiteSpace($UriObject.UserInfo)) {
            throw "Invalid ToastGUID format: URI contains '@' character (user info not allowed)"
        }

        # Convert ToastGUID to uppercase for validation (System.Uri lowercases it)
        $ToastGUID = $ToastGUID.ToUpper()

        # Extract path (Interval) - properly decoded
        $Interval = $UriObject.AbsolutePath.TrimStart('/').Trim()
        if ([string]::IsNullOrWhiteSpace($Interval)) {
            throw "URI missing path component (Interval)"
        }

        # CRITICAL: Validate after decoding to catch encoded bypass attempts
        if ($ToastGUID -notmatch '^[A-F0-9\-]{1,36}$') {
            throw "Invalid ToastGUID format: '$ToastGUID' (expected uppercase hex with hyphens)"
        }

        # Validate interval is exactly one of the allowed values
        if ($Interval -notin @('15m', '30m', '1h', '2h', '4h', 'eod')) {
            throw "Invalid interval: '$Interval' (expected one of: 15m, 30m, 1h, 2h, 4h, eod)"
        }

        # Verify no extra path components
        if ($UriObject.Segments.Count -gt 2) {
            throw "URI contains extra path components: $($UriObject.Segments -join ' ')"
        }

        # Verify no query string or fragment
        if (![string]::IsNullOrWhiteSpace($UriObject.Query)) {
            throw "URI contains unexpected query string: $($UriObject.Query)"
        }
        if (![string]::IsNullOrWhiteSpace($UriObject.Fragment)) {
            throw "URI contains unexpected fragment: $($UriObject.Fragment)"
        }

        Write-Verbose "URI parsing successful: ToastGUID=$ToastGUID, Interval=$Interval"
        Write-Verbose "URI components: Scheme=$($UriObject.Scheme), Host=$($UriObject.Host), Path=$($UriObject.AbsolutePath)"

        return @{
            ToastGUID = $ToastGUID
            Interval = $Interval
        }
    }
    catch {
        Write-Error "Failed to parse snooze URI: $($_.Exception.Message)"
        Write-Error "Provided URI: $Uri"
        throw
    }
}

#endregion Helper Functions

# Parse the protocol URI to extract ToastGUID and SnoozeInterval
try {
    $ParsedUri = Parse-SnoozeUri -Uri $ProtocolUri
    $ToastGUID = $ParsedUri.ToastGUID
    $SnoozeInterval = $ParsedUri.Interval
}
catch {
    Write-Error "FATAL: Failed to parse protocol URI: $ProtocolUri"
    Write-Error $_.Exception.Message
    exit 1
}

# Start logging
$LogPath = Join-Path $LogDirectory "$($ToastGuid)_Snooze.log"
# Ensure log directory exists
if (!(Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path $LogPath -Append

Write-Output "========================================="
Write-Output "Toast Snooze Handler Started"
Write-Output "ProtocolUri: $ProtocolUri"
Write-Output "ToastGUID: $ToastGUID"
Write-Output "SnoozeInterval: $SnoozeInterval"
Write-Output "Timestamp: $(Get-Date -Format 's')"
Write-Output "========================================="

# Registry path for this toast instance (dynamic based on deployment)
$RegPath = "${RegistryHive}:\${RegistryPath}\$ToastGUID"
Write-Output "Using registry path: $RegPath"

try {
    $ErrorActionPreference = 'Stop'

    # Read current state from registry
    Write-Output "Reading current state from registry..."
    if (!(Test-Path $RegPath)) {
        Write-Error "Registry path not found: $RegPath"
        Write-Error "Toast may not have been initialized properly."
        Stop-Transcript
        exit 1
    }

    $CurrentState = Get-ItemProperty -Path $RegPath -ErrorAction Stop
    $CurrentSnoozeCount = $CurrentState.SnoozeCount

    Write-Output "Current SnoozeCount: $CurrentSnoozeCount"

    # Validate snooze count (max 4)
    if ($CurrentSnoozeCount -ge 4) {
        Write-Error "Maximum snooze count (4) already reached. This should not happen."
        Stop-Transcript
        exit 1
    }

    # Increment snooze count
    $NewSnoozeCount = $CurrentSnoozeCount + 1
    Write-Output "New SnoozeCount will be: $NewSnoozeCount"

    # Calculate next trigger time based on interval
    $Now = Get-Date
    $NextTrigger = $null

    switch ($SnoozeInterval) {
        "15m" {
            $NextTrigger = $Now.AddMinutes(15)
            Write-Output "Snoozing for 15 minutes..."
        }
        "30m" {
            $NextTrigger = $Now.AddMinutes(30)
            Write-Output "Snoozing for 30 minutes..."
        }
        "1h" {
            $NextTrigger = $Now.AddMinutes(60)
            Write-Output "Snoozing for 1 hour..."
        }
        "2h" {
            $NextTrigger = $Now.AddMinutes(120)
            Write-Output "Snoozing for 2 hours..."
        }
        "4h" {
            $NextTrigger = $Now.AddMinutes(240)
            Write-Output "Snoozing for 4 hours..."
        }
        "eod" {
            # End of Day logic
            $Hour = $Now.Hour
            if ($Hour -lt 17) {
                # Before 5 PM - schedule for 5 PM today
                $NextTrigger = Get-Date -Hour 17 -Minute 0 -Second 0
                Write-Output "Snoozing until End of Day (5:00 PM today)..."
            }
            else {
                # After 5 PM - schedule for 9 AM tomorrow
                $NextTrigger = (Get-Date).AddDays(1)
                $NextTrigger = Get-Date -Date $NextTrigger -Hour 9 -Minute 0 -Second 0
                Write-Output "Snoozing until End of Day (9:00 AM tomorrow)..."
            }
        }
    }

    Write-Output "Next toast display scheduled for: $($NextTrigger.ToString('s'))"

    # Update registry with new state
    Write-Output "Updating registry..."
    try {
        Set-ItemProperty -Path $RegPath -Name "SnoozeCount" -Value $NewSnoozeCount -ErrorAction Stop
        Set-ItemProperty -Path $RegPath -Name "LastShown" -Value (Get-Date).ToString('s') -ErrorAction Stop
        Set-ItemProperty -Path $RegPath -Name "LastSnoozeInterval" -Value $SnoozeInterval -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {
        Write-Error "========================================"
        Write-Error "ACCESS DENIED - Registry Write Failed"
        Write-Error "========================================"
        Write-Error ""
        Write-Error "This error indicates incorrect deployment or GPO restrictions."
        Write-Error ""
        Write-Error "SOLUTIONS:"
        Write-Error "1. Re-deploy Toast_Notify.ps1 as SYSTEM with -EnableProgressive"
        Write-Error "   This will automatically grant necessary permissions to BUILTIN\Users"
        Write-Error ""
        Write-Error "2. Deploy with -RegistryHive HKCU for per-user state (no permissions needed)"
        Write-Error "   Example: Toast_Notify.ps1 -EnableProgressive -RegistryHive HKCU"
        Write-Error ""
        Write-Error "3. Manually grant permissions (PowerShell as Admin):"
        Write-Error "   `$Path = '$RegPath'"
        Write-Error "   `$Acl = Get-Acl -Path `$Path"
        Write-Error "   `$Rule = New-Object System.Security.AccessControl.RegistryAccessRule('BUILTIN\Users', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')"
        Write-Error "   `$Acl.AddAccessRule(`$Rule)"
        Write-Error "   Set-Acl -Path `$Path -AclObject `$Acl"
        Write-Error ""
        Write-Error "Registry Path: $RegPath"
        Write-Error "Current User: $env:USERNAME"
        Write-Error "Current Context: USER (not SYSTEM)"
        Write-Error "========================================"
        Stop-Transcript
        exit 1
    }
    catch {
        Write-Error "Failed to update registry: $($_.Exception.Message)"
        Stop-Transcript
        exit 1
    }

    # Verify registry write succeeded
    $Verify = Get-ItemProperty -Path $RegPath -ErrorAction Stop
    if ($Verify.SnoozeCount -ne $NewSnoozeCount) {
        throw "Registry write verification failed - SnoozeCount not updated correctly"
    }

    Write-Output "Registry updated and verified successfully"

    # Calculate task expiry (2 minutes after trigger)
    $Task_Expiry = $NextTrigger.AddMinutes(2).ToString('s')

    # Get the toast script path (should be in same directory as this handler)
    $CurrentDir = Split-Path $MyInvocation.MyCommand.Path
    $ToastScriptPath = Join-Path $CurrentDir "Toast_Notify.ps1"

    if (!(Test-Path $ToastScriptPath)) {
        Write-Warning "Toast_Notify.ps1 not found in $CurrentDir"
        Write-Warning "Attempting to use staged path in %WINDIR%\Temp..."
        $ToastScriptPath = Join-Path $ENV:Windir "Temp\$ToastGUID\Toast_Notify.ps1"
    }

    if (!(Test-Path $ToastScriptPath)) {
        Write-Error "Toast_Notify.ps1 not found in either location"
        Write-Error "Cannot create scheduled task for next snooze"
        Stop-Transcript
        exit 1
    }

    Write-Output "Toast script path: $ToastScriptPath"

    # Create scheduled task for next toast display
    Write-Output "Creating scheduled task..."
    $TaskName = "Toast_Notification_$($ToastGuid)_Snooze$NewSnoozeCount"

    # Remove old task if it exists
    $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($ExistingTask) {
        Write-Output "Removing existing task: $TaskName"
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    # Build task action with updated SnoozeCount parameter
    $Task_Action = New-ScheduledTaskAction `
        -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$ToastScriptPath"" -ToastGUID ""$ToastGUID"" -EnableProgressive -SnoozeCount $NewSnoozeCount"

    # Create trigger for calculated time
    $Task_Trigger = New-ScheduledTaskTrigger -Once -At $NextTrigger
    $Task_Trigger.EndBoundary = $Task_Expiry

    # Create principal (USERS group)
    $Task_Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited

    # Create settings
    $Task_Settings = New-ScheduledTaskSettingsSet `
        -Compatibility V1 `
        -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 600) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    # Build task
    $New_Task = New-ScheduledTask `
        -Description "Progressive Toast Notification - Snooze $NewSnoozeCount of 4. Next display at $($NextTrigger.ToString('g'))" `
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
        Write-Error "   Modify line 366 to:"
        Write-Error "   `$Task_Principal = New-ScheduledTaskPrincipal -UserId `$env:USERNAME"
        Write-Error ""
        Write-Error "4. Manual permission grant (PowerShell as Admin):"
        Write-Error "   schtasks /create /tn ""$TaskName"" /tr ""powershell.exe"" /sc once /st 00:00 /ru ""`$env:USERDOMAIN\`$env:USERNAME"""
        Write-Error "   (Note: For local users, use: /ru ""`$env:COMPUTERNAME\`$env:USERNAME"")"
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

    Write-Output "Scheduled task created successfully: $TaskName"
    Write-Output "Task will trigger at: $($NextTrigger.ToString('s'))"
    Write-Output "User snoozed to $($NextTrigger.ToString('g')), count now $NewSnoozeCount/4"

    # Verify task was created
    $VerifyTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($VerifyTask) {
        Write-Output "Task verification: [OK]"
    }
    else {
        Write-Error "Task verification: [FAIL] - Task not found after registration"
    }

    Write-Output "========================================="
    Write-Output "Toast Snooze Handler Completed Successfully"
    Write-Output "========================================="
}
catch {
    Write-Error "An error occurred in Toast_Snooze_Handler:"
    Write-Error $_.Exception.Message
    Write-Error $_.ScriptStackTrace
    Stop-Transcript
    exit 1
}

Stop-Transcript
exit 0
