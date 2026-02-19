<#
===========================================================================
Created on:   12/02/2026
Created by:   Ben Whitmore (with AI assistance)
Filename:     Toast_Snooze_Handler.ps1
===========================================================================

Version 1.12 - 19/02/2026
-FIX: Task arguments now forward -RegistryHive and -RegistryPath to Toast_Notify.ps1
 invocation, ensuring custom registry paths are preserved across snooze cycles.
 Previously the re-invoked script defaulted to SOFTWARE\ToastNotification, read
 no state, and always showed Stage 0 (2hr button) regardless of actual SnoozeCount.

Version 1.11 - 18/02/2026
-RebootCountdownMinutes now read from HKLM registry (stored by Toast_Notify.ps1 v2.30)
-RebootCountdownMinutes now included in snooze task action arguments
-Ensures configured countdown propagates through entire snooze task chain
-Fallback default: 5 minutes (matches Toast_Notify.ps1 parameter default)

Version 1.10 - 18/02/2026
-Cancel fallback task (Toast_Notification_{GUID}_{Username}_Fallback) after snooze task registered
-Fallback task is pre-scheduled by Toast_Notify.ps1 v2.26 before the toast is shown
-Ensures the snooze task is the authoritative next action, not the fallback
-Non-fatal: if fallback cancellation fails, logs warning and continues

Version 1.9 - 17/02/2026
-ARCHITECTURE CHANGE: Replaced pre-created task activation with dynamic task creation in user context
-ROOT CAUSE: All pre-created task principal types failed for standard user modification
  (GroupId/SeBatchLogonRight, InteractiveToken/UserId schema, InteractiveToken without UserId/service error)
-FIX: Standard users register tasks that run as themselves (-UserId $env:USERNAME -LogonType Interactive)
-FIX: XMLSource and ToastScenario read from registry (stored by Toast_Notify.ps1 v2.23 SYSTEM deployment)
-FIX: Secondary bug - previous task action args were missing -XMLSource and -ToastScenario parameters
-Task naming changed: Toast_Notification_{GUID}_Snooze{N} (unique per snooze count, auto-expires)
-Previous snooze task cleaned up via Unregister-ScheduledTask (non-fatal if already expired)

Version 1.8 - 17/02/2026
-FIX: Restructured task activation block - separate Get-ScheduledTask catch (task not found) from Set-ScheduledTask/Enable-ScheduledTask catch (activation failure)
-Resolves misleading 'PRE-CREATED TASK NOT FOUND' message when actual error was Set-ScheduledTask access denied
-CimException catch now ONLY fires when Get-ScheduledTask returns task-not-found, not when Set-ScheduledTask fails

Version 1.7 - 17/02/2026
-FIX: Added $ErrorActionPreference='Continue' at start of all catch blocks
-Prevents Write-Error in catch blocks from becoming terminating errors under $EAP='Stop'
-Root cause of "614 char 5" error: $EAP='Stop' set in outer try (line 264) cascaded through
 Write-Error calls inside inner catch blocks, causing them to throw and escape to outer catch
-Set-ScheduledTask error messages now properly logged instead of being swallowed by the cascade
-$ErrorActionPreference='Continue' resets error preference locally inside each catch block only

Version 1.6 - 17/02/2026
-Updated error messages: -EnableProgressive parameter renamed to -Snooze
-Removed -SnoozeCount 0 from deployment command examples
-No logic changes (snooze handler behavior unchanged)

Version 1.5.4 - 16/02/2026
-DIAGNOSTIC: Enhanced logging for trigger activation troubleshooting
-Added detailed diagnostics for Set-ScheduledTask and Enable-ScheduledTask operations
-Logs show: task state before/after, trigger details, error details with codes
-Added log file path, user context, and domain to startup output
-Helps diagnose why triggers not being set on corporate machines

Version 1.5.3 - 16/02/2026
-CRITICAL FIX: Remove settings update from Set-ScheduledTask to avoid credentials error
-Resolves "username or password is incorrect" error (0x8007052E) on corporate machines
-Only update trigger, not settings (settings already correct from SYSTEM pre-creation)
-Corporate GPO requires password validation when modifying group-based principal tasks
-Pre-created tasks from Toast_Notify.ps1 already have correct settings, no update needed

Version 1.5.2 - 16/02/2026
-COMPATIBILITY FIX: Removed DeleteExpiredTaskAfter parameter from task settings
-Resolves "task XML incorrectly formatted" error (0x8004131F) on corporate machines
-EndBoundary on trigger already prevents execution after expiry (no deletion needed)
-Pre-created tasks now persist (disabled after use) instead of auto-deleting
-Improves compatibility across Windows versions and GPO configurations

Version 1.5.1 - 16/02/2026
-ENHANCEMENT: Added task cleanup to prevent snooze task accumulation
-Disables previous snooze task before enabling next task
-Ensures only ONE snooze task is active at any time (prevents task swamping)
-Non-fatal error handling: cleanup failure doesn't block current snooze
-Tasks expire automatically per EndBoundary if disable fails (2-level protection)
-Maintains system-wide snooze counting via HKLM registry

Version 1.5 - 16/02/2026
-CRITICAL FIX: Replace Register-ScheduledTask with Set-ScheduledTask/Enable-ScheduledTask
-Uses pre-created disabled tasks from Toast_Notify.ps1 SYSTEM deployment (enterprise solution)
-Standard users modify existing tasks (Set/Enable) instead of creating new ones (Register)
-Eliminates Access Denied errors in standard user context (USER can modify, cannot create)
-Added comprehensive error handling for missing pre-created tasks
-Added deployment verification and helpful error messages
-Follows PSADT enterprise pattern: SYSTEM pre-creates, USER modifies

Version 1.4 - 16/02/2026
-BLOCKER FIX: Unregister-ScheduledTask wrapped in try-catch (lines 360-372)
-Prevents Access Denied on task deletion from terminating handler
-Task deletion failure is non-fatal: Register-ScheduledTask -Force overwrites existing task
-Improves reliability in environments with restricted Task Scheduler permissions
-Production-critical stability fix

Version 1.3 - 16/02/2026
-CRITICAL FIX: Reset ErrorActionPreference before scheduled task registration
-Ensures Register-ScheduledTask errors are caught by inner try-catch (lines 389-429)
-Prevents Access Denied errors from bypassing specific error handling to outer catch
-Fixes issue where $ErrorActionPreference='Stop' at line 203 caused terminating errors

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
        $ErrorActionPreference = 'Continue'
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
    $ErrorActionPreference = 'Continue'
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
Write-Output "Toast Snooze Handler Started (v1.9)"
Write-Output "========================================="
Write-Output "ProtocolUri: $ProtocolUri"
Write-Output "ToastGUID: $ToastGUID"
Write-Output "SnoozeInterval: $SnoozeInterval"
Write-Output "Timestamp: $(Get-Date -Format 's')"
Write-Output "Log File: $LogPath"
Write-Output "Log Directory: $LogDirectory"
Write-Output "Current User: $env:USERNAME"
Write-Output "Current Domain: $env:USERDOMAIN"
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

    # Read XMLSource and ToastScenario from registry (stored by SYSTEM deployment v2.23+).
    # These values are required to build correct task action arguments for the snooze task.
    # Without them the re-displayed toast would use the default CustomMessage.xml which may
    # not exist in the staged directory, causing the scheduled toast to fail silently.
    $StoredXMLSource = $CurrentState.XMLSource
    $StoredToastScenario = $CurrentState.ToastScenario
    if ([string]::IsNullOrEmpty($StoredXMLSource)) {
        Write-Warning "XMLSource not found in registry - using default CustomMessage.xml"
        $StoredXMLSource = "CustomMessage.xml"
    }
    if ([string]::IsNullOrEmpty($StoredToastScenario)) {
        $StoredToastScenario = "alarm"
    }
    Write-Output "Toast XMLSource: $StoredXMLSource"
    Write-Output "Toast Scenario: $StoredToastScenario"
    $StoredRebootCountdownMinutes = $CurrentState.RebootCountdownMinutes
    if (-not $StoredRebootCountdownMinutes -or $StoredRebootCountdownMinutes -lt 1) {
        Write-Warning "RebootCountdownMinutes not found in registry - using default 5 minutes"
        $StoredRebootCountdownMinutes = 5
    }
    Write-Output "Reboot Countdown: $StoredRebootCountdownMinutes minutes"

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
        $ErrorActionPreference = 'Continue'
        Write-Error "========================================"
        Write-Error "ACCESS DENIED - Registry Write Failed"
        Write-Error "========================================"
        Write-Error ""
        Write-Error "This error indicates incorrect deployment or GPO restrictions."
        Write-Error ""
        Write-Error "SOLUTIONS:"
        Write-Error "1. Re-deploy Toast_Notify.ps1 as SYSTEM with -Snooze"
        Write-Error "   This will automatically grant necessary permissions to BUILTIN\Users"
        Write-Error ""
        Write-Error "2. Deploy with -RegistryHive HKCU for per-user state (no permissions needed)"
        Write-Error "   Example: Toast_Notify.ps1 -Snooze -RegistryHive HKCU"
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
        $ErrorActionPreference = 'Continue'
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

    # Task expiry window: 3 days after trigger.
    # Allows the task to fire at the next login if the user was offline (e.g. midnight snooze,
    # user returns next morning). StartWhenAvailable picks it up on login within this window.
    $Task_Expiry = $NextTrigger.AddDays(3).ToString('s')

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

    # Create snooze scheduled task dynamically in user context (v1.9)
    # Architecture change: tasks are created by the USER at snooze time rather than pre-created by SYSTEM.
    # Standard users can register tasks that run as themselves (-UserId $env:USERNAME).
    # This eliminates all GroupId/SeBatchLogonRight and InteractiveToken/UserId schema failures.
    Write-Output "Creating snooze scheduled task..."
    $TaskName = "Toast_Notification_${ToastGUID}_$($env:USERNAME)_Snooze${NewSnoozeCount}"

    try {
        $ErrorActionPreference = 'Stop'

        # Build task components
        $TaskArguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass" +
            " -File `"$ToastScriptPath`"" +
            " -ToastGUID `"$ToastGUID`"" +
            " -XMLSource `"$StoredXMLSource`"" +
            " -ToastScenario `"$StoredToastScenario`"" +
            " -RebootCountdownMinutes $StoredRebootCountdownMinutes" +
            " -RegistryHive `"$RegistryHive`"" +
            " -RegistryPath `"$RegistryPath`"" +
            " -Snooze"
        $TaskAction = New-ScheduledTaskAction `
            -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" `
            -Argument $TaskArguments

        $TaskTrigger = New-ScheduledTaskTrigger -Once -At $NextTrigger
        $TaskTrigger.EndBoundary = $Task_Expiry

        $TaskPrincipal = New-ScheduledTaskPrincipal `
            -UserId $env:USERNAME `
            -LogonType Interactive `
            -RunLevel Limited

        $TaskSettings = New-ScheduledTaskSettingsSet `
            -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
            -StartWhenAvailable `
            -DeleteExpiredTaskAfter (New-TimeSpan -Hours 4)

        # Register the task - standard users can register tasks that run as themselves
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $TaskAction `
            -Trigger $TaskTrigger `
            -Principal $TaskPrincipal `
            -Settings $TaskSettings `
            -Force `
            -ErrorAction Stop | Out-Null

        Write-Output "[OK] Snooze task registered: $TaskName"
        Write-Output "     Fires at: $($NextTrigger.ToString('s'))"
        Write-Output "     Expires at: $Task_Expiry (3 days - StartWhenAvailable enabled)"
        Write-Output "     Runs as: $env:USERNAME (Interactive, Limited)"
        Write-Output "     XMLSource: $StoredXMLSource"
        Write-Output "     ToastScenario: $StoredToastScenario"

        # Cancel fallback task (pre-scheduled by Toast_Notify.ps1 to handle Learn More / timeout scenarios)
        # Now that user has clicked Snooze, the snooze task above is the authoritative next action.
        $FallbackTaskName = "Toast_Notification_${ToastGUID}_$($env:USERNAME)_Fallback"
        try {
            $FallbackTask = Get-ScheduledTask -TaskName $FallbackTaskName -ErrorAction SilentlyContinue
            if ($FallbackTask) {
                Unregister-ScheduledTask -TaskName $FallbackTaskName -Confirm:$false -ErrorAction Stop
                Write-Output "[OK] Fallback task cancelled: $FallbackTaskName"
            }
            else {
                Write-Output "[INFO] No fallback task found to cancel: $FallbackTaskName"
            }
        }
        catch {
            Write-Warning "[!] Could not cancel fallback task (non-fatal): $($_.Exception.Message)"
        }
    }
    catch {
        $ErrorActionPreference = 'Continue'
        Write-Error "========================================"
        Write-Error "FAILED TO CREATE SNOOZE TASK"
        Write-Error "========================================"
        Write-Error "Task: $TaskName"
        Write-Error "Error: $($_.Exception.Message)"
        Write-Error "Error Type: $($_.Exception.GetType().FullName)"
        Write-Error ""
        Write-Error "This should not occur - standard users can register tasks as themselves."
        Write-Error "Check if Task Scheduler service is running and user account is not restricted."
        Write-Error "========================================"
        Stop-Transcript
        exit 1
    }

    # Clean up previous snooze task (non-fatal - task may have already expired/auto-deleted)
    if ($NewSnoozeCount -gt 1) {
        $PreviousTaskName = "Toast_Notification_${ToastGUID}_$($env:USERNAME)_Snooze$($NewSnoozeCount - 1)"
        try {
            $PreviousTask = Get-ScheduledTask -TaskName $PreviousTaskName -ErrorAction SilentlyContinue
            if ($PreviousTask) {
                Unregister-ScheduledTask -TaskName $PreviousTaskName -Confirm:$false -ErrorAction Stop
                Write-Output "[OK] Cleaned up previous snooze task: $PreviousTaskName"
            }
            else {
                Write-Output "[INFO] Previous task already removed (auto-expired): $PreviousTaskName"
            }
        }
        catch {
            Write-Warning "Could not clean up previous task ${PreviousTaskName}: $($_.Exception.Message)"
            Write-Warning "Task will auto-delete per DeleteExpiredTaskAfter setting"
        }
    }
    else {
        Write-Output "[INFO] First snooze (count=1) - no previous task to clean up"
    }

    Write-Output ""
    Write-Output "[OK] Snooze activated successfully"
    Write-Output "     Next toast will appear at: $($NextTrigger.ToString('s'))"
    Write-Output "========================================="
    Write-Output "Toast Snooze Handler Completed Successfully"
    Write-Output "========================================="
}
catch {
    $ErrorActionPreference = 'Continue'
    Write-Error "An error occurred in Toast_Snooze_Handler:"
    Write-Error $_.Exception.Message
    Write-Error $_.ScriptStackTrace
    Stop-Transcript
    exit 1
}

Stop-Transcript
exit 0
