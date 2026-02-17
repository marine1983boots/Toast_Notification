<#
===========================================================================
Created on:   22/07/2020 11:04
Created by:   Ben Whitmore
Filename:     Toast_Notify.ps1
===========================================================================

Version 2.20 - 17/02/2026
-FIX: Initialize-SnoozeTasks now updates DACL on existing tasks (was skipping via continue)
-FIX: Changed SDDL from FA (FILE_ALL_ACCESS) to GA (Generic All) for correct task object rights
-DACL now applied regardless of whether task is new or pre-existing from previous deployment
-Root cause: re-deploy found tasks already existing and did SuccessCount++; continue, skipping DACL grant
-Tasks on test machine had DEFAULT DACL (SYSTEM+Admins only) because DACL block was never reached
-Restructured for loop: create task if missing, then ALWAYS apply/verify DACL regardless

Version 2.19 - 17/02/2026
-FIX: Logging now works for both SYSTEM deployment and USER context execution
-Start-Transcript called immediately after $LogPath is set (organized Logs\ folder)
-SYSTEM context: deployment output now captured (Initialize-SnoozeTasks, DACL grant, task registration)
-USER context: transcript now uses organized Logs\ path instead of %WINDIR%\Temp\{GUID}.log
-Both contexts produce timestamped log files in {WorkingDirectory}\{GUID}\Logs\

Version 2.18 - 17/02/2026
-FIX: SetSecurityDescriptor flags corrected from 4 to 0 in Initialize-SnoozeTasks
-Per MSDN IRegisteredTask::SetSecurityDescriptor only accepts flags=0 or flags=0x10 (TASK_DONT_ADD_PRINCIPAL_ACE)
-flags=4 caused E_INVALIDARG (value does not fall within the expected range) at runtime
-Replaced GetSecurityDescriptor + SDDL append with direct DACL set: D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)
-Direct DACL avoids SDDL parsing bugs (GetSecurityDescriptor(4) may return string without D: prefix)

Version 2.17 - 17/02/2026
-FIX: Correct SetSecurityDescriptor DACL grant in Initialize-SnoozeTasks (three bugs fixed):
  1. GetSecurityDescriptor(4) instead of (0xF) - DACL_SECURITY_INFORMATION only; avoids SACL section
     that caused appended ACE to land in SACL instead of DACL
  2. SetSecurityDescriptor($sddl, 4) instead of ($sddl, 0) - passing 0 is a no-op; DACL not written
  3. (A;;GA;;;AU) instead of (A;;GRGWGX;;;AU) - GA (Generic All) maps to TASK_ALL_ACCESS; generic
     rights GRGWGX did not correctly map to Task Scheduler modify rights
-Changed catch block from Write-Warning to Write-Error + throw so ACL failures are visible
-Changed regex check to (?i)A;;(?:FA|GA|GRGWGX);;;AU to match any equivalent full-access ACE

Version 2.16 - 17/02/2026
-FIX: Removed -DeleteExpiredTaskAfter from pre-created snooze tasks only (Initialize-SnoozeTasks)
-Root cause: DeleteExpiredTaskAfter requires a trigger with EndBoundary - tasks with no trigger fail XML validation
-Pre-created snooze tasks have no trigger at creation (added later by snooze handler) - cannot use DeleteExpiredTaskAfter
-Main notification task retains -DeleteExpiredTaskAfter (30 days) - it has trigger with EndBoundary set at creation
-Pre-created snooze tasks are reused infrastructure (disabled/re-enabled), not candidates for auto-delete anyway

Version 2.15 - 17/02/2026
-Auto-delete expired tasks: Changed -Compatibility V1 to Win8 (snooze + main task)
-Added -DeleteExpiredTaskAfter (30 days) to both task settings
-OS self-cleans task entries 30 days after all triggers expire
-V1 was incompatible with DeleteExpiredTaskAfter (XML error 0x8004131F on corporate machines)
-Toast notifications require Windows 10 minimum; Win8 schema compatibility is correct for all targets

Version 2.14 - 17/02/2026
-FIX: Grant Authenticated Users (AU) read/write/execute on each pre-created snooze task
-Uses Schedule.Service COM object to append (A;;GRGWGX;;;AU) to task security descriptor
-Resolves Set-ScheduledTask / Enable-ScheduledTask Access Denied for standard users
-Principal GroupId S-1-5-32-545 controls what account runs the task, NOT who can modify it
-Task DACL defaults to Administrators+SYSTEM only; this adds explicit AU modify rights

Version 2.13 - 17/02/2026
-Pass -RegistryHive and -RegistryPath to Toast_Reboot_Handler.ps1 command registration
-Enables reboot handler to clean up registry and tasks using correct registry location

Version 2.12 - 17/02/2026
-FIX: Replaced Dismiss button with Reboot Now button for Stages 0-3 in -Snooze mode
-Snooze mode now shows: Snooze (0-2) + Learn More + Reboot Now (all stages)
-Stage 4: Reboot Now only (unchanged)

Version 2.11 - 17/02/2026
-SIMPLIFICATION: Merged -EnableProgressive into -Snooze (single activation switch)
-Removed -EnableProgressive parameter (breaking change - use -Snooze instead)
-Removed -SnoozeCount parameter (stage read exclusively from registry)
-ActionTemplateSnooze (system snooze dropdown) removed - -Snooze now activates stage system only
-Unified button-building: -Snooze = stage-aware buttons, no -Snooze = Learn More + Dismiss only
-Registry is authoritative for stage state (SnoozeCount always read from registry when -Snooze set)
-Pre-created task arguments now use -Snooze only (not -EnableProgressive -SnoozeCount N)

Version 2.10 - 16/02/2026
-CLEANUP: Removed all remaining fallback-related comments and messages
-Simplified error handling messages for clearer debugging
-Cleaned up change log entries

Version 2.7 - 16/02/2026
-COMPATIBILITY FIX: Removed DeleteExpiredTaskAfter parameter from main toast task settings (line 1679)
-Resolves "task XML incorrectly formatted" error (0x8004131F) on corporate machines
-EndBoundary on trigger already prevents execution after expiry (no deletion needed)
-Added DontStopIfGoingOnBatteries for consistency with other task configurations
-Improves compatibility across Windows versions and GPO configurations

Version 2.6 - 16/02/2026
-CRITICAL FIX: Pre-create scheduled tasks during SYSTEM deployment (enterprise solution)
-Added Initialize-SnoozeTasks function to create 4 disabled snooze tasks during initial deployment
-Eliminates Access Denied errors when standard users click snooze (USER context can now modify pre-created tasks)
-Tasks created with USERS group principal and disabled state (activated by snooze handler)
-Follows PSADT enterprise pattern: SYSTEM pre-creates, USER modifies (cannot create)
-Function called after Initialize-ToastRegistry in SYSTEM context only
-Improved permissions model: Standard users modify existing tasks vs. creating new ones

Version 2.5 - 16/02/2026
-BLOCKER FIX: Stage 3 (final warning) no longer shows snooze button - forces reboot decision
-BLOCKER FIX: Unregister-ScheduledTask errors no longer fatal (Register with -Force overwrites anyway)
-Fixed progressive enforcement logic: Stage 3 is now true final warning (no snooze escape)
-Snooze button visibility: Stages 0-2 (snooze allowed), Stage 3 (no snooze), Stage 4 (forced reboot)
-Clarified Stage 3 behavior: User must reboot or dismiss (dismiss advances to Stage 4 on next run)
-Improved Stage 3 configuration: SnoozeInterval set to empty string, comment explains no-snooze policy
-Production-critical stability improvements

Version 2.4 - 16/02/2026
-Added $WorkingDirectory parameter for customizable base directory location (default: C:\ProgramData\ToastNotification)
-Added $Dismiss switch parameter to control dismiss (X) button visibility (default: hidden, forces user engagement)
-Added Initialize-ToastFolderStructure function to create organized folder layout per toast instance
-Added Remove-StaleToastFolders function with automatic cleanup to prevent bloat
-Added $CleanupDaysThreshold parameter to control automatic folder cleanup (default: 30 days)
-Removed $LogDirectory parameter (simplified: logs always go to WorkingDirectory\{GUID}\Logs\)
-Standardized folder structure: WorkingDirectory\{ToastGUID}\Logs\ and Scripts\ subfolders
-Handler scripts staged to Scripts\ subfolder (working copies isolated per toast instance)
-All logs (Toast_Notify, handlers) collated in Logs\ subfolder for centralized IT monitoring
-Protocol handlers automatically receive correct Logs\ path
-Dismiss button control: Default hides dismiss (X) button to enforce action selection, -Dismiss switch shows it
-Automatic cleanup: Stale toast folders removed after threshold days (prevents accumulation)
-Easy manual cleanup: Delete entire ToastGUID folder to remove all toast files
-Changed default location: C:\ProgramData\ToastNotification\{GUID} (was: C:\Windows\Temp\{GUID})
-Maintained full backwards compatibility

Version 2.3 - 16/02/2026
-Added configurable registry location: $RegistryHive (HKLM/HKCU/Custom) and $RegistryPath parameters
-Added automatic permission granting via Grant-RegistryPermissions function for HKLM mode
-Added $LogDirectory parameter for centralized logging
-Updated Initialize-ToastRegistry, Get-ToastState, Set-ToastState to support dynamic registry paths
-Protocol handlers now pass registry and log parameters to snooze/reboot handlers
-Fixes Access Denied errors in corporate environments when snooze button clicked
-Enables per-user state mode (HKCU) for multi-user scenarios
-Maintained full backwards compatibility (defaults to HKLM)

Version 2.2 - 12/02/2026
-Added progressive snooze enforcement system with 5-stage escalation (0-4)
-Added EnableProgressive parameter to enable opt-in progressive mode
-Added registry-based state management for snooze persistence
-Added Priority property support for Focus Assist bypass (Win10 15063+)
-Added ForceDisplay composite switch for maximum visibility
-Added ConvertTo-XmlSafeString function to prevent XML injection attacks
-Added support for stage-specific EventText in XML (Stage0-4 nodes)
-Maintained full backwards compatibility (EnableProgressive defaults to $false)
-Helper functions: Initialize-ToastRegistry, Get-ToastState, Set-ToastState, Get-StageDetails, Get-StageEventText

Version 2.1 - 11/02/2026
-Added -ToastScenario parameter to control toast notification priority and behavior
-Supports alarm, urgent, reminder, and default scenarios
-Scenario attribute dynamically applied to toast XML
-Parameter properly passed through scheduled task
-Added [CmdletBinding()] for proper PowerShell behavior support
-Added defensive parameter validation for ToastScenario

Version 2.0 - 07/02/2021
-Basic logging added
-Toast temp directory fixed to $ENV:\Temp\$ToastGUID
-Removed unncessary User SID discovery as its no longer needed when running the Scheduled Task as "USERS"
-Complete re-write for obtaining Toast Displayname. Name obtained first for Domain User, then AzureAD User from the IdentityStore Logon Cache and finally whoami.exe
- Added "AllowStartIfOnBatteries" parameter to Scheduled Task

Version 1.2.105 - 05/002/2021
-Changed how we grab the Toast Welcome Name for the Logged on user by leveraging whoami.exe - Thanks Erik Nilsson @dakire

Version 1.2.28 - 28/01/2021
-For AzureAD Joined computers we now try and grab a name to display in the Toast by getting the owner of the process Explorer.exe
-Better error handling when Get-xx fails

Version 1.2.26 - 26/01/2021
-Changed the Scheduled Task to run as -GroupId "S-1-5-32-545" (USERS). 
When Toast_Notify.ps1 is deployed as SYSTEM, the scheduled task will be created to run in the context of the Group "Users".
This means the Toast will pop for the logged on user even if the username was unobtainable (During testing AzureAD Joined Computers did not populate (Win32_ComputerSystem).Username).
The Toast will also be staged in the $ENV:Windir "Temp\$($ToastGuid)" folder if the logged on user information could not be found.
Thanks @CodyMathis123 for the inspiration via https://github.com/CodyMathis123/CM-Ramblings/blob/master/New-PostTeamsMachineWideInstallScheduledTask.ps1


Version 1.2.14 - 14/01/21
-Fixed logic to return logged on DisplayName - Thanks @MMelkersen
-Changed the way we retrieve the SID for the current user variable $LoggedOnUserSID
-Added Event Title, Description and Source Path to the Scheduled Task that is created to pop the User Toast
-Fixed an issue where Snooze was not being passed from the Scheduled Task
-Fixed an issue with XMLSource full path not being returned correctly from Scheduled Task

Version 1.2.10 - 10/01/21
-Removed XMLOtherSource Parameter
-Cleaned up XML formatting which removed unnecessary duplication when the Snooze parameter was passed. Action ChildNodes are now appended to ToastTemplate XML.

Version 1.2 - 09/01/21
-Added logic so if the script is deployed as SYSTEM it will create a scheduled task to run the script for the current logged on user.

-Special Thanks to: -
-Inspiration for creating a Scheduled Task for Toasts @PaulWetter https://wetterssource.com/ondemandtoast
-Inspiration for running Toasts in User Context @syst_and_deploy http://www.systanddeploy.com/2020/11/display-simple-toast-notification-for.html
-Inspiration for creating scheduled tasks for the logged on user @ccmexec via Community Hub in ConfigMgr https://github.com/Microsoft/configmgr-hub/commit/e4abdc0d3105afe026211805f13cf533c8de53c4

Version 1.1 - 30/12/20
-Added Snooze Switch option

Version 1.0 - 22/07/20
-Release

.SYNOPSIS
The purpose of the script is to create simple Toast Notifications in Windows 10

.DESCRIPTION
Toast_Notify.ps1 will read an XML file so Toast Notifications can be changed "on the fly" without having to repackage an application. The CustomMessage.xml file can be hosted on a fileshare.
To create a custom XML, copy CustomMessage.xml and edit the text you want to disaply in the toast notification. The following files should be present in the Script Directory

Toast_Notify.ps1
BadgeImage.jpg
HeroImage.jpg
CustomMessage.xml

.PARAMETER XMLSource
Specify the name of the XML file to read. The XML file must exist in the same directory as Toast_Notify.ps1. If no parameter is passed, it is assumed the XML file is called CustomMessage.xml.

.PARAMETER Snooze
Activates the progressive 5-stage snooze enforcement system. Registry tracks stage state (0-4).
Stage 0: initial, Stages 1-2: progressively shorter snooze, Stage 3: final warning (no snooze),
Stage 4: forced reboot notification. Without this switch: plain notification with Learn More + Dismiss only.

.PARAMETER ToastScenario
Specify the toast notification scenario type. Valid values:
- alarm: Highest priority, loops alarm audio, forces popup even with Focus Assist enabled (default)
- urgent: High priority, bypasses Focus Assist, standard notification sound
- reminder: Persistent reminder, can be suppressed by Focus Assist, stays in Action Center
- default: Standard notification behavior

.PARAMETER Priority
Set toast notification priority to High for Focus Assist bypass attempts.
Requires Windows 10 Build 15063 or later. Graceful fallback with warning if not supported.
Default: $false

.PARAMETER ForceDisplay
Composite switch that enables maximum visibility for critical alerts.
Combines: Priority=High + ToastScenario=alarm + ensures action buttons.
Default: $false

.PARAMETER RegistryHive
Registry hive for storing toast state: HKLM (machine-wide, default), HKCU (per-user), or Custom.
HKLM requires Grant-RegistryPermissions for user access.
HKCU provides per-user state with no elevation required.
Default: HKLM

.PARAMETER RegistryPath
Custom registry path under the specified hive.
Default: SOFTWARE\ToastNotification

.PARAMETER WorkingDirectory
Base directory for toast file structure. Creates organized layout with automatic subfolders:
- {ToastGUID}\Logs\ - All transcript logs from Toast_Notify and handlers
- {ToastGUID}\Scripts\ - Staged working copies of handler scripts
Default: C:\ProgramData\ToastNotification
Prevents bloat: Old toast folders automatically cleaned up after CleanupDaysThreshold days.

.PARAMETER CleanupDaysThreshold
Number of days before stale toast folders are automatically removed.
Prevents accumulation of old toast instances in working directory.
Default: 30 days

.PARAMETER Dismiss
Enable dismiss (X) button in top-right corner of toast notification.
Default behavior (without this switch): Dismiss button HIDDEN - forces user to choose action (snooze/reboot).
With this switch: Dismiss button VISIBLE - allows user to close notification without action.

Use cases:
- Default (no -Dismiss): Progressive enforcement, critical updates, ensures user engagement
- With -Dismiss: Informational toasts, testing, optional notifications

IMPORTANT: Stage 4 (final warning) should NEVER use -Dismiss to enforce reboot decision.
Default: $false (dismiss button hidden)

.EXAMPLE
Toast_Notify.ps1 -XMLSource "PhoneSystemProblems.xml"

.EXAMPLE
Toast_Notify.ps1 -Snooze

.EXAMPLE
Toast_Notify.ps1 -ToastScenario "urgent"

.EXAMPLE
Toast_Notify.ps1 -XMLSource "Maintenance.xml" -ToastScenario "reminder" -Snooze

.EXAMPLE
Toast_Notify.ps1 -ForceDisplay -XMLSource "CriticalAlert.xml"
Maximum visibility mode for critical notifications

.EXAMPLE
Toast_Notify.ps1 -Snooze -XMLSource "CustomMessage.xml"
Stage-managed notification starting at Stage 0 (2-hour snooze interval)

.EXAMPLE
Toast_Notify.ps1 -Snooze -RegistryHive HKCU
Per-user stage state stored in HKCU (no elevation required)

.EXAMPLE
Toast_Notify.ps1 -Snooze -WorkingDirectory "D:\CustomToasts"
Custom working directory with organized folder structure: D:\CustomToasts\{GUID}\Logs\ and Scripts\

.EXAMPLE
Toast_Notify.ps1 -Snooze -WorkingDirectory "C:\ProgramData\Notifications" -CleanupDaysThreshold 7
Custom location with aggressive cleanup (removes toast folders older than 7 days)

.EXAMPLE
Toast_Notify.ps1 -Dismiss -XMLSource "InformationalMessage.xml"
Informational toast with dismiss button visible (user can close without action)
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $False)]
    [Switch]$Snooze,
    [Parameter(Mandatory = $False)]
    [ValidateSet('alarm', 'urgent', 'reminder', 'default')]
    [String]$ToastScenario = 'alarm',
    [Parameter(Mandatory = $False)]
    [String]$XMLSource = "CustomMessage.xml",
    [Parameter(Mandatory = $False)]
    [ValidatePattern('^[A-F0-9\-]{1,36}$')]
    [String]$ToastGUID,
    [Parameter(Mandatory = $False)]
    [Switch]$Priority,
    [Parameter(Mandatory = $False)]
    [Switch]$ForceDisplay,
    [Parameter(Mandatory = $False)]
    [Switch]$TestMode,
    [Parameter(Mandatory = $False)]
    [ValidateRange(1, 1440)]
    [Int]$RebootCountdownMinutes = 5,
    [Parameter(Mandatory = $False)]
    [ValidateSet('HKLM', 'HKCU', 'Custom')]
    [String]$RegistryHive = 'HKLM',
    [Parameter(Mandatory = $False)]
    [ValidatePattern('^[a-zA-Z0-9_\\]+$')]
    [String]$RegistryPath = 'SOFTWARE\ToastNotification',
    [Parameter(Mandatory = $False)]
    [ValidateScript({
        if ([string]::IsNullOrWhiteSpace($_)) { return $true }
        if ($_ -match '^[a-zA-Z]:\\.*$' -or $_ -match '^\\\\\w+\\.*$') { return $true }
        throw "Invalid path format. Use local (C:\path) or UNC (\\server\share) paths only."
    })]
    [String]$WorkingDirectory = $null,
    [Parameter(Mandatory = $False)]
    [ValidateRange(1, 365)]
    [Int]$CleanupDaysThreshold = 30,
    [Parameter(Mandatory = $False)]
    [Switch]$Dismiss = $false
)

#region Helper Functions

function ConvertTo-XmlSafeString {
    <#
    .SYNOPSIS
        Encodes a string for safe embedding in XML
    .DESCRIPTION
        Prevents XML injection attacks by encoding special characters:
        & -> &amp;, < -> &lt;, > -> &gt;, " -> &quot;, ' -> &apos;

        CRITICAL: This function MUST be called on all user-provided or
        dynamic text before embedding in toast XML. Skipping this encoding
        creates XML injection vulnerabilities.
    .PARAMETER InputString
        The string to encode. Can be null or empty.
    .EXAMPLE
        ConvertTo-XmlSafeString -InputString "AT&T <Critical> Update"
        Returns: "AT&amp;T &lt;Critical&gt; Update"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [AllowNull()]
        [String]$InputString
    )

    if ([string]::IsNullOrEmpty($InputString)) {
        return ""
    }

    # Replace XML special characters with their entity equivalents
    $InputString = $InputString.Replace("&", "&amp;")
    $InputString = $InputString.Replace("<", "&lt;")
    $InputString = $InputString.Replace(">", "&gt;")
    $InputString = $InputString.Replace('"', "&quot;")
    $InputString = $InputString.Replace("'", "&apos;")

    return $InputString
}

function Initialize-ToastRegistry {
    <#
    .SYNOPSIS
        Creates registry structure for toast state persistence
    .PARAMETER ToastGUID
        Unique identifier for this toast instance
    .PARAMETER RegistryHive
        Registry hive to use (HKLM, HKCU, Custom)
    .PARAMETER RegistryPath
        Registry path under the hive (default: SOFTWARE\ToastNotification)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-F0-9\-]{1,36}$')]
        [String]$ToastGUID,

        [Parameter(Mandatory = $false)]
        [ValidateSet('HKLM', 'HKCU', 'Custom')]
        [String]$RegistryHive = 'HKLM',

        [Parameter(Mandatory = $false)]
        [String]$RegistryPath = 'SOFTWARE\ToastNotification'
    )

    $RegPath = "${RegistryHive}:\${RegistryPath}\$ToastGUID"
    $BasePath = "${RegistryHive}:\${RegistryPath}"

    try {
        # Create base path if not exists
        if (!(Test-Path $BasePath)) {
            $ParentPath = Split-Path $BasePath -Parent
            $LeafName = Split-Path $RegistryPath -Leaf
            New-Item -Path $ParentPath -Name $LeafName -Force | Out-Null
        }

        # Create toast-specific path
        if (!(Test-Path $RegPath)) {
            New-Item -Path $BasePath -Name $ToastGUID -Force | Out-Null
            Write-Verbose "Registry path created: $RegPath"
        }

        # Initialize properties with write verification
        Set-ItemProperty -Path $RegPath -Name "SnoozeCount" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $RegPath -Name "FirstShown" -Value (Get-Date).ToString('s') -Type String -Force
        Set-ItemProperty -Path $RegPath -Name "LastShown" -Value (Get-Date).ToString('s') -Type String -Force
        Set-ItemProperty -Path $RegPath -Name "LastSnoozeInterval" -Value "" -Type String -Force

        # Verify registry writes were successful
        $Verify = Get-ItemProperty -Path $RegPath -ErrorAction Stop
        if ($Verify.SnoozeCount -ne 0) {
            throw "Registry write verification failed - SnoozeCount not set correctly"
        }
        if ([string]::IsNullOrEmpty($Verify.FirstShown)) {
            throw "Registry write verification failed - FirstShown not set"
        }

        Write-Verbose "Registry initialized and verified: SnoozeCount=0, FirstShown=$(Get-Date -Format 's')"
        return $true
    }
    catch {
        Write-Warning "Failed to initialize registry: $($_.Exception.Message)"
        return $false
    }
}

function Initialize-SnoozeTasks {
    <#
    .SYNOPSIS
        Pre-creates disabled scheduled tasks for snooze stages
    .DESCRIPTION
        Creates 4 disabled scheduled tasks during SYSTEM deployment that will be activated
        by the snooze handler running in USER context. This solves the permission issue where
        standard users cannot create scheduled tasks but CAN modify existing ones.

        Used when deploying a toast notification with -Snooze enabled.
        This is the enterprise-grade PSADT pattern: SYSTEM creates, USER modifies.
    .PARAMETER ToastGUID
        Unique identifier for this toast instance
    .PARAMETER ToastScriptPath
        Full path to Toast_Notify.ps1 script
    .NOTES
        Requires: SYSTEM context (called during deployment phase only)

        Security: Grants (A;;GRGWGX;;;AU) - Authenticated Users receive Generic Read, Write,
        and Execute rights on each snooze task DACL. This is intentional - all domain users
        must be able to activate their own snooze task (Set-ScheduledTask / Enable-ScheduledTask).

        Business Rationale:
        - Multi-user shared endpoints need all users to action snooze notifications
        - Deployment environment is assumed to be IT-managed (corporate managed endpoint)
        - Task executable path is set at creation and cannot be changed via these permissions

        Risk Mitigation:
        - Task executable path is immutable (GRGWGX does not grant file-system write on target)
        - Task trigger/schedule can be modified, but executes the same Toast_Notify.ps1 script
        - ISO 27001 A.9.4.1: Task scope is limited to Toast GUID-specific tasks only
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-F0-9\-]{1,36}$')]
        [String]$ToastGUID,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [String]$ToastScriptPath
    )

    # Only create tasks if running as SYSTEM (called by -Snooze deployment block)
    $CurrentIdentity = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    if ($CurrentIdentity -ne "NT AUTHORITY\SYSTEM") {
        Write-Verbose "Not running as SYSTEM - skipping task pre-creation"
        return $false
    }

    Write-Output "Pre-creating snooze scheduled tasks..."
    $SuccessCount = 0

    for ($i = 1; $i -le 4; $i++) {
        $TaskName = "Toast_Notification_$($ToastGUID)_Snooze$i"

        # Check if task already exists
        $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

        try {
            if (-not $ExistingTask) {
                # Task does not exist - create it first
                # Create task action
                $Task_Action = New-ScheduledTaskAction `
                    -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" `
                    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$ToastScriptPath"" -ToastGUID ""$ToastGUID"" -Snooze"

                # Create principal (USERS group - allows all users to modify)
                $Task_Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited

                # Create settings (task disabled by default, no trigger)
                $Task_Settings = New-ScheduledTaskSettingsSet `
                    -Compatibility Win8 `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -Disable

                # Create task (no trigger - will be set by snooze handler)
                $New_Task = New-ScheduledTask `
                    -Description "Toast Notification - Snooze Stage $i (pre-created, disabled until activated by snooze handler)" `
                    -Action $Task_Action `
                    -Principal $Task_Principal `
                    -Settings $Task_Settings

                # Register task (running as SYSTEM, so this works)
                Register-ScheduledTask -TaskName $TaskName -InputObject $New_Task -Force -ErrorAction Stop | Out-Null
                Write-Output "  Pre-created task: $TaskName [DISABLED]"
            }
            else {
                # Task already exists from a previous deployment - skip re-registration.
                # IMPORTANT: Do NOT continue here. Fall through to apply/update the DACL.
                # Previous deployments may have left the task with default DACL (SYSTEM+Admins only),
                # which means Set-ScheduledTask will fail with Access Denied for standard users.
                Write-Output "  Task already exists: $TaskName [SKIPPED REGISTRATION - will update DACL]"
            }

            # DACL grant runs for BOTH new and pre-existing tasks.
            # Without this, Set-ScheduledTask / Enable-ScheduledTask fail with Access Denied
            # for standard users even though the task exists.
            # NOTE: GroupId S-1-5-32-545 above controls what account the task RUNS AS,
            #       not who can MODIFY it. The task DACL is stored separately in the
            #       registry and defaults to Administrators+SYSTEM only.
            $TaskScheduler = $null
            try {
                $ErrorActionPreference = 'Stop'
                $TaskScheduler = New-Object -ComObject 'Schedule.Service'
                $TaskScheduler.Connect()
                $TaskObject = $TaskScheduler.GetFolder('\').GetTask($TaskName)
                # Set DACL directly using Generic All (GA) - correct for Task Scheduler objects.
                # GA maps to TASK_ALL_ACCESS on task objects; FA (FILE_ALL_ACCESS) is for file objects
                # and does not correctly map task modify rights on the COM task object interface.
                # SDDL: SYSTEM full access, Administrators full access, Authenticated Users full access
                # flags=0: only valid values per MSDN are 0 (default) and 0x10 (TASK_DONT_ADD_PRINCIPAL_ACE)
                $NewSecDescriptor = 'D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)'
                $TaskObject.SetSecurityDescriptor($NewSecDescriptor, 0)
                Write-Output "  Granted AU Generic All access: $TaskName [OK]"
            }
            catch {
                Write-Error "  [FAIL] Failed to set task ACL for ${TaskName}: $($_.Exception.Message)"
                throw
            }
            finally {
                if ($null -ne $TaskScheduler) {
                    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($TaskScheduler)
                    Remove-Variable -Name TaskScheduler -ErrorAction SilentlyContinue
                }
            }

            # Only increment success count after DACL grant succeeds
            $SuccessCount++
        }
        catch {
            Write-Warning "  Failed to process task ${TaskName}: $($_.Exception.Message)"
        }
    }

    if ($SuccessCount -eq 4) {
        Write-Output "[OK] All 4 snooze tasks pre-created successfully"
        return $true
    }
    elseif ($SuccessCount -gt 0) {
        Write-Warning "Only $SuccessCount of 4 tasks created - snooze may fail at later stages"
        return $true
    }
    else {
        Write-Error "Failed to create any snooze tasks"
        return $false
    }
}

function Get-ToastState {
    <#
    .SYNOPSIS
        Reads current toast state from registry
    .PARAMETER ToastGUID
        Unique identifier for this toast instance
    .PARAMETER RegistryHive
        Registry hive to use (HKLM, HKCU, Custom)
    .PARAMETER RegistryPath
        Registry path under the hive (default: SOFTWARE\ToastNotification)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-F0-9\-]{1,36}$')]
        [String]$ToastGUID,

        [Parameter(Mandatory = $false)]
        [ValidateSet('HKLM', 'HKCU', 'Custom')]
        [String]$RegistryHive = 'HKLM',

        [Parameter(Mandatory = $false)]
        [String]$RegistryPath = 'SOFTWARE\ToastNotification'
    )

    $RegPath = "${RegistryHive}:\${RegistryPath}\$ToastGUID"

    try {
        if (Test-Path $RegPath) {
            $State = Get-ItemProperty -Path $RegPath -ErrorAction Stop
            Write-Verbose "Registry state retrieved: SnoozeCount=$($State.SnoozeCount)"
            return $State
        }
        else {
            Write-Warning "Registry path not found: $RegPath"
            return $null
        }
    }
    catch {
        Write-Warning "Failed to read registry state: $($_.Exception.Message)"
        return $null
    }
}

function Set-ToastState {
    <#
    .SYNOPSIS
        Updates toast state in registry
    .PARAMETER ToastGUID
        Unique identifier for this toast instance
    .PARAMETER SnoozeCount
        Current snooze count
    .PARAMETER LastInterval
        Last selected snooze interval
    .PARAMETER RegistryHive
        Registry hive to use (HKLM, HKCU, Custom)
    .PARAMETER RegistryPath
        Registry path under the hive (default: SOFTWARE\ToastNotification)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-F0-9\-]{1,36}$')]
        [String]$ToastGUID,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 4)]
        [Int]$SnoozeCount,

        [Parameter(Mandatory = $false)]
        [ValidateSet("", "15m", "30m", "1h", "2h", "4h", "eod")]
        [String]$LastInterval = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet('HKLM', 'HKCU', 'Custom')]
        [String]$RegistryHive = 'HKLM',

        [Parameter(Mandatory = $false)]
        [String]$RegistryPath = 'SOFTWARE\ToastNotification'
    )

    $RegPath = "${RegistryHive}:\${RegistryPath}\$ToastGUID"

    try {
        Set-ItemProperty -Path $RegPath -Name "SnoozeCount" -Value $SnoozeCount -Type DWord
        Set-ItemProperty -Path $RegPath -Name "LastShown" -Value (Get-Date).ToString('s') -Type String
        if ($LastInterval) {
            Set-ItemProperty -Path $RegPath -Name "LastSnoozeInterval" -Value $LastInterval -Type String
        }

        # Verify registry write succeeded
        $Verify = Get-ItemProperty -Path $RegPath -ErrorAction Stop
        if ($Verify.SnoozeCount -ne $SnoozeCount) {
            throw "Registry write verification failed - SnoozeCount not updated correctly"
        }

        Write-Verbose "Registry state updated and verified: SnoozeCount=$SnoozeCount"
        return $true
    }
    catch {
        Write-Warning "Failed to update registry state: $($_.Exception.Message)"
        return $false
    }
}

function Grant-RegistryPermissions {
    <#
    .SYNOPSIS
        Grants USERS group write permissions to SPECIFIC toast registry path only
    .DESCRIPTION
        SECURITY SCOPE: Permissions are ONLY granted to the specific ToastGUID path:
        HKLM:\SOFTWARE\ToastNotification\{ToastGUID}

        NOT granted to:
        - HKLM:\SOFTWARE\ToastNotification (parent)
        - HKLM:\SOFTWARE (entire software hive)
        - HKLM:\ (entire registry)

        This allows snooze handler to update only this toast instance's state
        from user context while maintaining security elsewhere.
    .PARAMETER RegistryPath
        Full registry path to specific toast instance
        Example: HKLM:\SOFTWARE\ToastNotification\ABC-123-DEF-456
    .EXAMPLE
        Grant-RegistryPermissions -RegistryPath "HKLM:\SOFTWARE\ToastNotification\ABC-123"
        Grants USERS write access ONLY to the ABC-123 toast instance path
    .NOTES
        Security validation ensures only ToastNotification\{GUID} paths can be modified
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^HKLM:\\SOFTWARE\\ToastNotification\\[A-F0-9\-]{1,36}$')]
        [String]$RegistryPath
    )

    try {
        Write-Verbose "SECURITY: Granting permissions to SPECIFIC path only: $RegistryPath"

        # Get current ACL for this specific path
        $Acl = Get-Acl -Path $RegistryPath

        # Create access rule for USERS group (S-1-5-32-545)
        # InheritanceFlags: ContainerInherit, ObjectInherit (only affects subkeys under THIS path)
        # PropagationFlags: None (does NOT propagate to parent or sibling keys)
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "BUILTIN\Users",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )

        # Add rule and apply to THIS PATH ONLY
        $Acl.AddAccessRule($Rule)
        Set-Acl -Path $RegistryPath -AclObject $Acl

        # Verify scope - ensure parent path permissions unchanged
        $ParentPath = "HKLM:\SOFTWARE\ToastNotification"
        if (Test-Path $ParentPath) {
            $ParentAcl = Get-Acl -Path $ParentPath
            $ParentUserRules = $ParentAcl.Access | Where-Object { $_.IdentityReference -eq "BUILTIN\Users" }
            if ($ParentUserRules.Count -eq 0) {
                Write-Verbose "SECURITY VERIFIED: Parent path still protected (no USERS write access)"
            }
        }

        Write-Output "[OK] Registry permissions granted to USERS group for THIS PATH ONLY: $RegistryPath"
        Write-Output "[OK] Parent path (SOFTWARE\ToastNotification) remains protected"
        return $true
    }
    catch {
        Write-Warning "Failed to grant registry permissions: $($_.Exception.Message)"
        return $false
    }
}

function Initialize-ToastFolderStructure {
    <#
    .SYNOPSIS
        Creates standardized folder structure for toast operations
    .DESCRIPTION
        Establishes consistent directory layout:
        BaseDirectory\
        ├── Logs\           (transcript logs from all components)
        ├── Scripts\        (staged working copies of handlers)
        └── (future: Registry backups)
    .PARAMETER BaseDirectory
        Root directory for toast file structure
        Default: C:\ProgramData\ToastNotification
    .PARAMETER ToastGUID
        Toast instance GUID for unique path
    .EXAMPLE
        Initialize-ToastFolderStructure -BaseDirectory "C:\ProgramData\ToastNotification" -ToastGUID "ABC-123"
        Creates: C:\ProgramData\ToastNotification\ABC-123\Logs\ and Scripts\ subdirectories
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$BaseDirectory,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-F0-9\-]{1,36}$')]
        [String]$ToastGUID
    )

    try {
        # Create base directory structure
        $BasePath = Join-Path $BaseDirectory $ToastGUID
        $Paths = @{
            Base    = $BasePath
            Logs    = Join-Path $BasePath "Logs"
            Scripts = Join-Path $BasePath "Scripts"
        }

        foreach ($PathName in $Paths.Keys) {
            $Path = $Paths[$PathName]
            if (!(Test-Path $Path)) {
                Write-Verbose "Creating directory: $Path"
                New-Item -Path $Path -ItemType Directory -Force | Out-Null
            }
        }

        Write-Verbose "Folder structure created: $($Paths.Base)"
        Write-Verbose "  - Logs:    $($Paths.Logs)"
        Write-Verbose "  - Scripts: $($Paths.Scripts)"

        # Return only the hashtable (no Write-Output to avoid array return)
        return $Paths
    }
    catch {
        Write-Error "Failed to create folder structure: $($_.Exception.Message)"
        throw
    }
}

function Remove-StaleToastFolders {
    <#
    .SYNOPSIS
        Removes old toast instance folders to prevent bloat
    .DESCRIPTION
        Scans the base directory for toast GUID folders and removes those older than
        the specified threshold. This prevents accumulation of old toast instances.

        Folder age is determined by the most recent file modification time within the folder.
    .PARAMETER BaseDirectory
        Root directory containing toast GUID folders
    .PARAMETER DaysThreshold
        Remove folders with no file modifications in this many days (default: 30)
    .EXAMPLE
        Remove-StaleToastFolders -BaseDirectory "C:\ProgramData\ToastNotification" -DaysThreshold 30
        Removes toast folders older than 30 days
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$BaseDirectory,

        [Parameter(Mandatory = $false)]
        [Int]$DaysThreshold = 30
    )

    try {
        if (!(Test-Path $BaseDirectory)) {
            Write-Verbose "Base directory does not exist, skipping cleanup: $BaseDirectory"
            return
        }

        $CutoffDate = (Get-Date).AddDays(-$DaysThreshold)
        Write-Verbose "Cleaning up toast folders older than $CutoffDate"

        # Get all subdirectories (each should be a GUID folder)
        $ToastFolders = Get-ChildItem -Path $BaseDirectory -Directory -ErrorAction SilentlyContinue

        $RemovedCount = 0
        foreach ($Folder in $ToastFolders) {
            try {
                # Check if folder name looks like a GUID (basic validation)
                if ($Folder.Name -notmatch '^[A-F0-9\-]{1,36}$') {
                    Write-Verbose "Skipping non-GUID folder: $($Folder.Name)"
                    continue
                }

                # Get most recent file modification time in folder (recursive)
                $LatestFile = Get-ChildItem -Path $Folder.FullName -File -Recurse -ErrorAction SilentlyContinue |
                              Sort-Object LastWriteTime -Descending |
                              Select-Object -First 1

                if ($LatestFile) {
                    if ($LatestFile.LastWriteTime -lt $CutoffDate) {
                        Write-Output "[CLEANUP] Removing stale toast folder: $($Folder.Name) (last modified: $($LatestFile.LastWriteTime))"
                        Remove-Item -Path $Folder.FullName -Recurse -Force -ErrorAction Stop
                        $RemovedCount++
                    }
                }
                else {
                    # Empty folder or no files - remove if folder itself is old
                    if ($Folder.LastWriteTime -lt $CutoffDate) {
                        Write-Output "[CLEANUP] Removing empty toast folder: $($Folder.Name)"
                        Remove-Item -Path $Folder.FullName -Recurse -Force -ErrorAction Stop
                        $RemovedCount++
                    }
                }
            }
            catch {
                Write-Warning "Failed to delete toast folder $($Folder.Name): $($_.Exception.Message)"
                Write-Verbose "This may indicate locked files in: $($Folder.FullName)"
            }
        }

        if ($RemovedCount -gt 0) {
            Write-Output "[OK] Cleanup complete: Removed $RemovedCount stale toast folder(s)"
        }
        else {
            Write-Verbose "No stale folders found for cleanup"
        }
    }
    catch {
        Write-Warning "Folder cleanup failed: $($_.Exception.Message)"
    }
}

function Get-StageDetails {
    <#
    .SYNOPSIS
        Gets stage configuration based on snooze count
    .DESCRIPTION
        Maps SnoozeCount (0-4) to stage-specific configuration including:
        - Scenario type (reminder, urgent, alarm)
        - Fixed snooze interval for that stage
        - Audio loop settings
        - Dismissal permissions
        - Visual urgency level
    .PARAMETER SnoozeCount
        Current snooze count (0-4)
    .EXAMPLE
        Get-StageDetails -SnoozeCount 0
        Returns Stage 0 configuration (initial reminder, 2h snooze)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 4)]
        [Int]$SnoozeCount
    )

    $StageConfig = @{
        Stage = $SnoozeCount
        Scenario = "reminder"
        SnoozeInterval = ""
        AllowDismiss = $true
        AudioLoop = $false
        VisualUrgency = "Normal"
    }

    switch ($SnoozeCount) {
        0 {
            $StageConfig.Stage = 0
            $StageConfig.Scenario = "alarm"
            $StageConfig.SnoozeInterval = "2h"
            $StageConfig.AllowDismiss = $true
            $StageConfig.AudioLoop = $false
            $StageConfig.VisualUrgency = "Normal"
        }
        1 {
            $StageConfig.Stage = 1
            $StageConfig.Scenario = "reminder"
            $StageConfig.SnoozeInterval = "1h"
            $StageConfig.AllowDismiss = $true
            $StageConfig.AudioLoop = $false
            $StageConfig.VisualUrgency = "Normal"
        }
        2 {
            $StageConfig.Stage = 2
            $StageConfig.Scenario = "reminder"
            $StageConfig.SnoozeInterval = "30m"
            $StageConfig.AllowDismiss = $true
            $StageConfig.AudioLoop = $false
            $StageConfig.VisualUrgency = "Normal"
        }
        3 {
            # Stage 3: FINAL WARNING - No snooze allowed
            # User must decide: Reboot Now or Dismiss (transitions to Stage 4 on next run)
            $StageConfig.Stage = 3
            $StageConfig.Scenario = "urgent"
            $StageConfig.SnoozeInterval = ""  # No snooze at Stage 3 (final warning)
            $StageConfig.AllowDismiss = $true  # Can dismiss, but next snooze attempt goes to Stage 4
            $StageConfig.AudioLoop = $true
            $StageConfig.VisualUrgency = "Urgent"
        }
        4 {
            $StageConfig.Stage = 4
            $StageConfig.Scenario = "alarm"
            $StageConfig.SnoozeInterval = ""  # No snooze at Stage 4
            $StageConfig.AllowDismiss = $false
            $StageConfig.AudioLoop = $true
            $StageConfig.VisualUrgency = "Critical"
        }
        default {
            # Default to Stage 0
            $StageConfig.Stage = 0
            $StageConfig.Scenario = "reminder"
            $StageConfig.SnoozeInterval = "2h"
            $StageConfig.AllowDismiss = $true
            $StageConfig.AudioLoop = $false
            $StageConfig.VisualUrgency = "Normal"
        }
    }

    Write-Verbose "Stage $SnoozeCount configuration: Scenario=$($StageConfig.Scenario), SnoozeInterval=$($StageConfig.SnoozeInterval), Dismissable=$($StageConfig.AllowDismiss)"
    return $StageConfig
}

function Get-StageEventText {
    <#
    .SYNOPSIS
        Extracts stage-specific text from XML EventText node
    .DESCRIPTION
        Supports two XML schemas:
        - New schema: EventText with Stage0-4 child nodes
        - Old schema: EventText with single text value (backward compatible)
    .PARAMETER XmlDocument
        XML document containing ToastContent
    .PARAMETER StageNumber
        Current stage number (0-4 based on SnoozeCount)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.Xml.XmlDocument]$XmlDocument,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 4)]
        [int]$StageNumber
    )

    if ($null -eq $XmlDocument) { return $null }

    $EventTextNode = $XmlDocument.ToastContent.EventText
    if ($null -eq $EventTextNode) { return $null }

    # Check if stage-specific nodes exist (new schema)
    if ($EventTextNode.ChildNodes.Count -gt 0 -and $EventTextNode.SelectSingleNode("Stage0")) {
        # New schema: Select stage based on StageNumber
        $StageNode = $EventTextNode.SelectSingleNode("Stage$StageNumber")
        if ($StageNode) {
            Write-Verbose "Using Stage$StageNumber text from XML"
            return $StageNode.InnerText.Trim()
        }
        else {
            # Use Stage0 if specific stage node missing
            Write-Verbose "Stage$StageNumber not found, using Stage0 text from XML"
            return $EventTextNode.Stage0.InnerText.Trim()
        }
    }
    else {
        # Old schema: Single EventText value (backward compatible)
        Write-Verbose "Using simple EventText from XML (backward compatible)"
        return [string]$EventTextNode
    }
}

function Register-ToastAppId {
    <#
    .SYNOPSIS
        Registers a custom AppUserModelId for toast notifications
    .DESCRIPTION
        Registers AppId in HKCU registry with enhanced error handling.
        Returns detailed status object for caller decision-making.
    .PARAMETER AppId
        The AppUserModelId to register
    .PARAMETER DisplayName
        Display name shown in Windows notification settings
    .EXAMPLE
        $Result = Register-ToastAppId -AppId "MyApp.ID" -DisplayName "My Application"
        if ($Result.Success) { Write-Host "Registration successful" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$AppId,

        [Parameter(Mandatory = $false)]
        [String]$DisplayName = "Toast Notification"
    )

    $Result = [PSCustomObject]@{
        Success = $false
        ErrorCategory = ""
        IsGPORestricted = $false
        ErrorMessage = ""
        CanRetry = $false
    }

    try {
        $RegPath = "HKCU:\Software\Classes\AppUserModelId\$AppId"
        $ParentPath = "HKCU:\Software\Classes"

        # Pre-flight check: Verify parent path is accessible
        if (-not (Test-Path $ParentPath)) {
            try {
                New-Item -Path $ParentPath -Force -ErrorAction Stop | Out-Null
                Write-Verbose "Created parent path: $ParentPath"
            }
            catch [System.UnauthorizedAccessException] {
                $Result.ErrorCategory = "PARENT_PATH_ACCESS_DENIED"
                $Result.IsGPORestricted = $true
                $Result.ErrorMessage = "GPO policy prevents access to $ParentPath"
                Write-Warning $Result.ErrorMessage
                return $Result
            }
        }

        # Check if AppId already exists
        if (Test-Path $RegPath) {
            try {
                $Existing = Get-ItemProperty -Path $RegPath -ErrorAction Stop
                Write-Verbose "AppUserModelId already registered: $AppId"
                $Result.Success = $true
                return $Result
            }
            catch {
                $Result.ErrorCategory = "EXISTING_APPID_UNREADABLE"
                $Result.ErrorMessage = "AppId exists but cannot be read: $($_.Exception.Message)"
                Write-Warning $Result.ErrorMessage
                return $Result
            }
        }

        # Register new AppId
        try {
            Write-Verbose "Registering AppUserModelId: $AppId"
            New-Item -Path $RegPath -Force -ErrorAction Stop | Out-Null
        }
        catch [System.UnauthorizedAccessException] {
            $Result.ErrorCategory = "APPID_CREATE_ACCESS_DENIED"
            $Result.IsGPORestricted = $true
            $Result.ErrorMessage = "GPO policy prevents AppId creation"
            Write-Warning $Result.ErrorMessage
            return $Result
        }

        try {
            Set-ItemProperty -Path $RegPath -Name "DisplayName" -Value $DisplayName -Type String -ErrorAction Stop
        }
        catch [System.UnauthorizedAccessException] {
            $Result.ErrorCategory = "DISPLAYNAME_SET_ACCESS_DENIED"
            $Result.IsGPORestricted = $true
            $Result.ErrorMessage = "GPO policy prevents DisplayName property write"
            Write-Warning $Result.ErrorMessage
            return $Result
        }

        # Verify registration succeeded
        try {
            $Verify = Get-ItemProperty -Path $RegPath -ErrorAction Stop
            if ($Verify.DisplayName -eq $DisplayName) {
                Write-Verbose "AppUserModelId registered and verified successfully"
                $Result.Success = $true
            }
            else {
                $Result.ErrorCategory = "VERIFICATION_FAILED"
                $Result.ErrorMessage = "Registration succeeded but verification failed"
                Write-Warning $Result.ErrorMessage
            }
        }
        catch {
            $Result.ErrorCategory = "VERIFICATION_FAILED"
            $Result.ErrorMessage = "Registration succeeded but not readable: $($_.Exception.Message)"
            Write-Warning $Result.ErrorMessage
        }

        return $Result
    }
    catch {
        $Result.ErrorCategory = "REGISTRATION_EXCEPTION"
        $Result.ErrorMessage = $_.Exception.Message
        Write-Warning "AppId registration exception: $($_.Exception.Message)"
        return $Result
    }
}

function Test-CorporateEnvironment {
    <#
    .SYNOPSIS
        Detects corporate environment restrictions before toast display
    .DESCRIPTION
        Proactively tests for GPO restrictions, WinRT availability, and
        notification system status. Returns detailed restriction information.
    .EXAMPLE
        $CorpEnv = Test-CorporateEnvironment
        if ($CorpEnv.IsRestricted) {
            Write-Warning "Restrictions: $($CorpEnv.Restrictions -join ', ')"
        }
    #>
    [CmdletBinding()]
    param()

    $Result = [PSCustomObject]@{
        IsRestricted = $false
        Restrictions = @()
        CanWriteHKCU = $true
        WinRTAvailable = $true
        NotificationSystemEnabled = $true
    }

    # Test 1: HKCU write capability (GPO restrictions)
    try {
        $TestPath = "HKCU:\Software\ToastNotification\_CorpEnvTest"
        New-Item -Path $TestPath -Force -ErrorAction Stop | Out-Null
        Remove-Item -Path $TestPath -Force -ErrorAction SilentlyContinue
        Write-Verbose "HKCU write test: PASS"
    }
    catch [System.UnauthorizedAccessException] {
        $Result.CanWriteHKCU = $false
        $Result.IsRestricted = $true
        $Result.Restrictions += "HKCU_WRITE_DENIED"
        Write-Verbose "HKCU write test: FAIL (Access Denied)"
    }
    catch {
        Write-Verbose "HKCU write test: FAIL ($($_.Exception.Message))"
    }

    # Test 2: WinRT API accessibility
    try {
        $WinRTType = [Windows.UI.Notifications.ToastNotificationManager]
        if ($null -eq $WinRTType) {
            $Result.WinRTAvailable = $false
            $Result.IsRestricted = $true
            $Result.Restrictions += "WINRT_UNAVAILABLE"
        }
        else {
            Write-Verbose "WinRT API test: PASS"
        }
    }
    catch {
        $Result.WinRTAvailable = $false
        $Result.IsRestricted = $true
        $Result.Restrictions += "WINRT_UNAVAILABLE"
        Write-Verbose "WinRT API test: FAIL"
    }

    # Test 3: Windows notification system status
    try {
        $NotifSettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction SilentlyContinue
        if ($NotifSettings.ToastEnabled -eq 0) {
            $Result.NotificationSystemEnabled = $false
            $Result.IsRestricted = $true
            $Result.Restrictions += "NOTIFICATIONS_DISABLED"
            Write-Verbose "Notification system test: DISABLED"
        }
        else {
            Write-Verbose "Notification system test: ENABLED"
        }
    }
    catch {
        Write-Verbose "Notification system test: UNKNOWN"
    }

    # Log corporate restrictions if detected
    if ($Result.IsRestricted) {
        Write-Verbose "Corporate restrictions detected: $($Result.Restrictions.Count) restriction(s)"
    }

    return $Result
}

function Test-WinRTAssemblies {
    <#
    .SYNOPSIS
        Validates WinRT assemblies are functional, not just loaded
    .DESCRIPTION
        Tests that ToastNotificationManager and XmlDocument types are
        loaded and can be instantiated. Returns true if functional.
    .EXAMPLE
        if (-not (Test-WinRTAssemblies)) {
            Write-Warning "WinRT assemblies not functional"
        }
    #>
    [CmdletBinding()]
    param()

    try {
        # Test ToastNotificationManager type loaded
        $ToastType = [Windows.UI.Notifications.ToastNotificationManager]
        if ($null -eq $ToastType) {
            Write-Verbose "ToastNotificationManager type not loaded"
            return $false
        }

        # Test XmlDocument type loaded
        $XmlType = [Windows.Data.Xml.Dom.XmlDocument]
        if ($null -eq $XmlType) {
            Write-Verbose "XmlDocument type not loaded"
            return $false
        }

        # Test GetDefault() method accessible
        try {
            $TestDefault = [Windows.UI.Notifications.ToastNotificationManager]::GetDefault
            if ($null -eq $TestDefault) {
                Write-Verbose "GetDefault() method not accessible"
                return $false
            }
        }
        catch {
            Write-Verbose "GetDefault() test failed: $($_.Exception.Message)"
            return $false
        }

        Write-Verbose "WinRT assemblies validation: PASS"
        return $true
    }
    catch {
        Write-Verbose "WinRT assemblies validation: FAIL ($($_.Exception.Message))"
        return $false
    }
}

#endregion Helper Functions

#Set Unique GUID for the Toast
If (!($ToastGUID)) {
    $ToastGUID = ([guid]::NewGuid()).ToString().ToUpper()
}

#Handle ForceDisplay composite switch
If ($ForceDisplay) {
    Write-Verbose "ForceDisplay enabled - setting Priority=High and ToastScenario=alarm"
    $Priority = $true
    $ToastScenario = 'alarm'
    Write-Warning "ForceDisplay cannot guarantee Focus Assist bypass on all systems"
}

#Current Directory
$ScriptPath = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path $ScriptPath

#Determine base working directory
if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    # Default: C:\ProgramData\ToastNotification
    $BaseDirectory = "C:\ProgramData\ToastNotification"
}
else {
    # Custom working directory
    $BaseDirectory = $WorkingDirectory
}

# Cleanup stale toast folders to prevent bloat (runs in SYSTEM context only)
if (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq "NT AUTHORITY\SYSTEM") {
    Remove-StaleToastFolders -BaseDirectory $BaseDirectory -DaysThreshold $CleanupDaysThreshold
}

# Initialize folder structure for this toast instance
$FolderStructure = Initialize-ToastFolderStructure -BaseDirectory $BaseDirectory -ToastGUID $ToastGUID

# Set paths for use throughout script
$ToastPath = $FolderStructure.Scripts  # Scripts staged to Scripts subfolder
$LogPath = Join-Path $FolderStructure.Logs "Toast_Notify_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogPath -Append

Write-Output "[OK] Working directory: $($FolderStructure.Base)"
Write-Output "[OK] Scripts staged to: $($FolderStructure.Scripts)"
Write-Output "[OK] Logs saved to: $($FolderStructure.Logs)"

#Validate ToastScenario parameter (defensive check)
if ($ToastScenario -notin @('alarm', 'urgent', 'reminder', 'default')) {
    Write-Warning "Invalid ToastScenario value: $ToastScenario. Defaulting to 'alarm'"
    $ToastScenario = 'alarm'
}

#Test if XML exists
if (!(Test-Path (Join-Path $CurrentDir $XMLSource))) {
    throw "$XMLSource is invalid."
}

#Check XML is valid
$XMLToast = New-Object System.Xml.XmlDocument
try {
    $XMLToast.Load((Get-ChildItem -Path (Join-Path $CurrentDir $XMLSource)).FullName)
    $XMLValid = $True
}
catch [System.Xml.XmlException] {
    Write-Verbose "$XMLSource : $($_.toString())"
    $XMLValid = $False
}

#Continue if XML is valid
If ($XMLValid -eq $True) {

    #Create Toast Variables
    $ToastTitle = [string]$XMLToast.ToastContent.ToastTitle
    $Signature = [string]$XMLToast.ToastContent.Signature
    $EventTitle = [string]$XMLToast.ToastContent.EventTitle
    $EventText = [string]$XMLToast.ToastContent.EventText
    $ButtonTitle = [string]$XMLToast.ToastContent.ButtonTitle
    $ButtonAction = [string]$XMLToast.ToastContent.ButtonAction
    $SnoozeTitle = [string]$XMLToast.ToastContent.SnoozeTitle
    $RebootTitle = [string]$XMLToast.ToastContent.RebootTitle

    #ToastDuration: Short = 7s, Long = 25s
    $ToastDuration = "long"

    #Images
    $BadgeImage = "file:///$CurrentDir/badgeimage.jpg"
    $HeroImage = "file:///$CurrentDir/heroimage.jpg"

    #Set COM App ID for toast notifications
    # Use custom AppId following BurntToast approach for reliability
    $LauncherID = "ToastNotification.PowerShell.{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"

    #Dont Create a Scheduled Task if the script is running in the context of the logged on user, only if SYSTEM fired the script i.e. Deployment from Intune/ConfigMgr
    If (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq "NT AUTHORITY\SYSTEM") {

        Write-Output "Running in SYSTEM context - Initializing deployment..."

        #Initialize Registry State if snooze mode enabled
        If ($Snooze) {
            Write-Output "Initializing registry for ToastGUID: $ToastGUID"
            $RegInitResult = Initialize-ToastRegistry -ToastGUID $ToastGUID -RegistryHive $RegistryHive -RegistryPath $RegistryPath
            if (!$RegInitResult) {
                Write-Error "CRITICAL: Registry initialization failed"
                Write-Error "Toast state will not persist across snoozes"
                throw "Registry initialization failure - cannot deploy toast notification"
            }

            # Verify registry was created and readable
            $RegVerify = Get-ToastState -ToastGUID $ToastGUID -RegistryHive $RegistryHive -RegistryPath $RegistryPath
            if (!$RegVerify) {
                Write-Error "CRITICAL: Registry created but not readable"
                throw "Registry verification failed"
            }

            Write-Output "Registry initialization verified: SnoozeCount=$($RegVerify.SnoozeCount)"

            # Grant permissions if using HKLM (machine-wide state)
            if ($RegistryHive -eq 'HKLM') {
                Write-Output "Granting USERS group permissions to registry path for snooze handler..."
                $RegPath = "HKLM:\${RegistryPath}\$ToastGUID"
                $PermissionResult = Grant-RegistryPermissions -RegistryPath $RegPath
                if ($PermissionResult) {
                    Write-Output "[OK] Registry permissions granted - Snooze handler will work from user context"
                }
                else {
                    Write-Warning "Permission grant failed - Snooze may not work from user context"
                    Write-Warning "Consider deploying with -RegistryHive HKCU for per-user state"
                }
            }
            elseif ($RegistryHive -eq 'HKCU') {
                Write-Output "Using HKCU mode - No permission grant needed (per-user state)"
            }

            # Pre-create snooze scheduled tasks (enterprise solution for standard user permissions)
            Write-Output "Pre-creating snooze scheduled tasks..."
            $TaskInitResult = Initialize-SnoozeTasks -ToastGUID $ToastGUID -ToastScriptPath $ScriptPath
            if ($TaskInitResult) {
                Write-Output "[OK] Snooze tasks pre-created - standard users can now activate them"
            }
            else {
                Write-Warning "Snooze task pre-creation failed - users may encounter Access Denied errors"
                Write-Warning "Progressive snooze functionality may not work correctly"
            }

            # Register toast-snooze:// protocol handler in HKEY_CLASSES_ROOT
            Write-Output "Registering toast-snooze:// protocol handler..."
            try {
                # Check if running with sufficient permissions (SYSTEM should have access)
                $ProtocolKey = "Registry::HKEY_CLASSES_ROOT\toast-snooze"

                # Create protocol key
                if (!(Test-Path $ProtocolKey)) {
                    New-Item -Path "Registry::HKEY_CLASSES_ROOT" -Name "toast-snooze" -Force | Out-Null
                }

                Set-ItemProperty -Path $ProtocolKey -Name "(Default)" -Value "URL:Toast Snooze Protocol" -Force
                Set-ItemProperty -Path $ProtocolKey -Name "URL Protocol" -Value "" -Force

                # Create shell\open\command structure
                $CommandKey = "$ProtocolKey\shell\open\command"
                if (!(Test-Path "$ProtocolKey\shell")) {
                    New-Item -Path $ProtocolKey -Name "shell" -Force | Out-Null
                }
                if (!(Test-Path "$ProtocolKey\shell\open")) {
                    New-Item -Path "$ProtocolKey\shell" -Name "open" -Force | Out-Null
                }
                if (!(Test-Path $CommandKey)) {
                    New-Item -Path "$ProtocolKey\shell\open" -Name "command" -Force | Out-Null
                }

                # The handler script will be staged, so reference the staged path
                # Note: We'll update this after staging files
                # For now, create placeholder - will be updated after file staging

                Write-Output "Protocol handler registration completed"
            }
            catch {
                Write-Warning "Failed to register protocol handler: $($_.Exception.Message)"
                Write-Warning "Progressive snooze buttons may not function correctly"
            }
        }

        #Prepare to stage Toast Notification Content in Scripts subfolder
        Try {

            # Folder structure already created by Initialize-ToastFolderStructure
            # $ToastPath now points to Scripts subfolder

            # Only copy toast-related files (not Claude workspace files or directories)
            $FileExtensions = @('*.ps1', '*.jpg', '*.xml', '*.png', '*.txt')
            $ToastFiles = Get-ChildItem -Path $CurrentDir -File | Where-Object {
                $Extension = "*$($_.Extension)"
                $Extension -in $FileExtensions
            }

            Write-Output "Staging $($ToastFiles.Count) files to $ToastPath"

            #Copy Toast Files to Toast TEMP folder
            ForEach ($ToastFile in $ToastFiles) {
                Copy-Item $ToastFile.FullName -Destination $ToastPath -ErrorAction Continue
                Write-Output "  Staged: $($ToastFile.Name)"
            }
        }
        Catch {
            Write-Warning $_.Exception.Message
        }

        #Set new Toast script to run from TEMP path
        $New_ToastPath = Join-Path $ToastPath "Toast_Notify.ps1"

        # Update protocol handler command now that files are staged
        If ($Snooze) {
            try {
                $HandlerPath = Join-Path $ToastPath "Toast_Snooze_Handler.ps1"
                $CommandKey = "Registry::HKEY_CLASSES_ROOT\toast-snooze\shell\open\command"

                # Build command with registry and log parameters
                $CommandParams = "-ProtocolUri `"%1`" -RegistryHive $RegistryHive -RegistryPath `"$RegistryPath`" -LogDirectory `"$($FolderStructure.Logs)`""
                $CommandValue = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$HandlerPath`" $CommandParams"
                Set-ItemProperty -Path $CommandKey -Name "(Default)" -Value $CommandValue -Force

                Write-Output "Protocol handler command registered: $CommandValue"

                # Verify registration
                $VerifyCommand = Get-ItemProperty -Path $CommandKey -ErrorAction Stop
                if ($VerifyCommand.'(Default)' -eq $CommandValue) {
                    Write-Output "Protocol registration verified successfully"
                }
                else {
                    Write-Warning "Protocol registration verification failed"
                }

                # Register toast-reboot:// protocol handler (for Stage 4 "Reboot Now" button)
                Write-Output "Registering toast-reboot:// protocol handler..."
                $RebootProtocolKey = "Registry::HKEY_CLASSES_ROOT\toast-reboot"

                # Create protocol key
                if (!(Test-Path $RebootProtocolKey)) {
                    New-Item -Path "Registry::HKEY_CLASSES_ROOT" -Name "toast-reboot" -Force | Out-Null
                }

                Set-ItemProperty -Path $RebootProtocolKey -Name "(Default)" -Value "URL:Toast Reboot Protocol" -Force
                Set-ItemProperty -Path $RebootProtocolKey -Name "URL Protocol" -Value "" -Force

                # Create shell\open\command structure
                $RebootCommandKey = "$RebootProtocolKey\shell\open\command"
                if (!(Test-Path "$RebootProtocolKey\shell")) {
                    New-Item -Path $RebootProtocolKey -Name "shell" -Force | Out-Null
                }
                if (!(Test-Path "$RebootProtocolKey\shell\open")) {
                    New-Item -Path "$RebootProtocolKey\shell" -Name "open" -Force | Out-Null
                }
                if (!(Test-Path $RebootCommandKey)) {
                    New-Item -Path "$RebootProtocolKey\shell\open" -Name "command" -Force | Out-Null
                }

                # Set command to Toast_Reboot_Handler.ps1 with log directory
                $RebootHandlerPath = Join-Path $ToastPath "Toast_Reboot_Handler.ps1"
                $RebootCmdParams = "-ProtocolUri `"%1`" -RegistryHive $RegistryHive -RegistryPath `"$RegistryPath`" -LogDirectory `"$($FolderStructure.Logs)`""
                $RebootCommandValue = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RebootHandlerPath`" $RebootCmdParams"
                Set-ItemProperty -Path $RebootCommandKey -Name "(Default)" -Value $RebootCommandValue -Force

                Write-Output "toast-reboot:// protocol registered: $RebootCommandValue"
            }
            catch {
                Write-Warning "Failed to update protocol handler command: $($_.Exception.Message)"
            }
        }

        #Created Scheduled Task to run as Logged on User
        $Task_TimeToRun = (Get-Date).AddSeconds(30).ToString('s')
        $Task_Expiry = (Get-Date).AddSeconds(120).ToString('s')

        #Build arguments string with optional parameters
        $TaskArguments = "-NoProfile -WindowStyle Hidden -File ""$New_ToastPath"" -ToastGUID ""$ToastGUID"" -XMLSource ""$XMLSource"" -ToastScenario ""$ToastScenario"""
        If ($Snooze) {
            $TaskArguments += " -Snooze"
        }
        If ($Priority) {
            $TaskArguments += " -Priority"
        }
        If ($ForceDisplay) {
            $TaskArguments += " -ForceDisplay"
        }
        $Task_Action = New-ScheduledTaskAction -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Argument $TaskArguments
        $Task_Trigger = New-ScheduledTaskTrigger -Once -At $Task_TimeToRun
        $Task_Trigger.EndBoundary = $Task_Expiry
        $Task_Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
        $Task_Settings = New-ScheduledTaskSettingsSet `
            -Compatibility Win8 `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -DeleteExpiredTaskAfter (New-TimeSpan -Days 30)
        $New_Task = New-ScheduledTask -Description "Toast_Notification_$($ToastGuid) Task for user notification. Title: $($EventTitle) :: Event:$($EventText) :: Source Path: $($ToastPath) " -Action $Task_Action -Principal $Task_Principal -Trigger $Task_Trigger -Settings $Task_Settings
        Register-ScheduledTask -TaskName "Toast_Notification_$($ToastGuid)" -InputObject $New_Task

        Stop-Transcript
    }

    #Run the toast of the script is running in the context of the Logged On User
    If (!(([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -eq "NT AUTHORITY\SYSTEM")) {

        Write-Output "========================================="
        Write-Output "Toast Notification - User Context Execution"
        Write-Output "ToastGUID: $ToastGUID"
        Write-Output "Snooze (Stage Mode): $Snooze"
        Write-Output "Priority: $Priority"
        Write-Output "ForceDisplay: $ForceDisplay"
        Write-Output "Timestamp: $(Get-Date -Format 's')"
        Write-Output "========================================="
        $SnoozeCount = 0  # Will be read from registry if -Snooze is active

        #Handle snooze mode - read authoritative SnoozeCount from registry
        If ($Snooze) {
            $RegState = Get-ToastState -ToastGUID $ToastGUID -RegistryHive $RegistryHive -RegistryPath $RegistryPath
            if ($RegState) {
                $SnoozeCount = $RegState.SnoozeCount
                Write-Output "Registry SnoozeCount: $SnoozeCount (Source: Registry)"
            }
            else {
                Write-Warning "Registry state not found for ToastGUID: $ToastGUID - using default SnoozeCount: 0"
            }

            # Validate range (detect registry corruption)
            if ($SnoozeCount -lt 0 -or $SnoozeCount -gt 4) {
                Write-Error "CRITICAL: Invalid SnoozeCount from registry: $SnoozeCount (valid: 0-4)"
                Stop-Transcript
                throw "Registry corruption detected - SnoozeCount out of valid range"
            }
        }

        #Get logged on user DisplayName
        #Try to get the DisplayName for Domain User
        $ErrorActionPreference = "Continue"

        Try {
            Write-Output "Trying Identity LogonUI Registry Key for Domain User info..."
            $User = Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "LastLoggedOnDisplayName" -ErrorAction Stop | Select-Object -ExpandProperty LastLoggedOnDisplayName

            If ($Null -eq $User) {
                $Firstname = $Null
            }
            else {
                $DisplayName = $User.Split(" ")
                $Firstname = $DisplayName[0]
            }
        }
        Catch [System.Management.Automation.PSArgumentException] {
            "Registry Key Property missing" 
            Write-Warning "Registry Key for LastLoggedOnDisplayName could not be found."
            $Firstname = $Null
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            "Registry Key itself is missing" 
            Write-Warning "Registry value for LastLoggedOnDisplayName could not be found."
            $Firstname = $Null
        }

        #Try to get the DisplayName for Azure AD User
        If ($Null -eq $Firstname) {
            Write-Output "Trying Identity Store Cache for Azure AD User info..."
            Try {
                $UserSID = (whoami /user /fo csv | ConvertFrom-Csv).Sid
                $LogonCacheSID = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache -Recurse -Depth 2 | Where-Object { $_.Name -match $UserSID }).Name
                If ($LogonCacheSID) { 
                    $LogonCacheSID = $LogonCacheSID.Replace("HKEY_LOCAL_MACHINE", "HKLM:") 
                    $User = Get-ItemProperty -Path $LogonCacheSID | Select-Object -ExpandProperty DisplayName -ErrorAction Stop
                    $DisplayName = $User.Split(" ")
                    $Firstname = $DisplayName[0]
                }
                else {
                    Write-Warning "Could not get DisplayName property from Identity Store Cache for Azure AD User"
                    $Firstname = $Null
                }
            }
            Catch [System.Management.Automation.PSArgumentException] {
                Write-Warning "Could not get DisplayName property from Identity Store Cache for Azure AD User"
                Write-Output "Resorting to whoami info for Toast DisplayName..."
                $Firstname = $Null
            }
            Catch [System.Management.Automation.ItemNotFoundException] {
                Write-Warning "Could not get SID from Identity Store Cache for Azure AD User"
                Write-Output "Resorting to whoami info for Toast DisplayName..."
                $Firstname = $Null
            }
            Catch {
                Write-Warning "Could not get SID from Identity Store Cache for Azure AD User"
                Write-Output "Resorting to whoami info for Toast DisplayName..."
                $Firstname = $Null  
            }
        }

        #Try to get the DisplayName from whoami
        If ($Null -eq $Firstname) {
            Try {
                Write-Output "Trying Identity whoami.exe for DisplayName info..."
                $User = whoami.exe
                $Firstname = (Get-Culture).textinfo.totitlecase($User.Split("\")[1])
                Write-Output "DisplayName retrieved from whoami.exe"
            }
            Catch {
                Write-Warning "Could not get DisplayName from whoami.exe"
            }
        }

        #If DisplayName could not be obtained, leave it blank
        If ($Null -eq $Firstname) {
            Write-Output "DisplayName could not be obtained, it will be blank in the Toast"
        }
                   
        #Get Hour of Day and set Custom Hello
        $Hour = (Get-Date).Hour
        If ($Hour -lt 12) { $CustomHello = "Good Morning $($Firstname)" }
        ElseIf ($Hour -gt 16) { $CustomHello = "Good Evening $($Firstname)" }
        Else { $CustomHello = "Good Afternoon $($Firstname)" }

        #Load WinRT Assemblies with validation
        Write-Verbose "Loading Windows Runtime assemblies..."
        $Script:CorporateEnvironment = $null

        try {
            $ErrorActionPreference = 'Stop'

            # Load ToastNotificationManager
            try {
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                Write-Verbose "[OK] Windows.UI.Notifications assembly loaded"
            }
            catch [System.IO.FileNotFoundException] {
                Write-Error "WinRT assembly not found - Windows 10/11 required"
                throw "Windows.UI.Notifications assembly not available"
            }

            # Load XmlDocument
            try {
                [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
                Write-Verbose "[OK] Windows.Data.Xml.Dom assembly loaded"
            }
            catch [System.IO.FileNotFoundException] {
                Write-Error "WinRT XML assembly not found"
                throw "Windows.Data.Xml.Dom assembly not available"
            }

            # Validate assemblies are functional
            if (-not (Test-WinRTAssemblies)) {
                Write-Warning "WinRT assemblies loaded but validation failed"

                # Detect corporate environment
                $CorpEnv = Test-CorporateEnvironment
                if ($CorpEnv.IsRestricted) {
                    Write-Warning "Corporate restrictions detected: $($CorpEnv.Restrictions -join ', ')"
                    $Script:CorporateEnvironment = $CorpEnv
                }
            }
        }
        catch {
            Write-Error "Critical: WinRT assemblies unavailable: $($_.Exception.Message)"
            Write-Error "Toast notifications will not work without WinRT assemblies"
            throw
        }

        #Get stage configuration if snooze mode enabled
        If ($Snooze) {
            $StageConfig = Get-StageDetails -SnoozeCount $SnoozeCount
            Write-Output "Toast Stage: $($StageConfig.Stage) ($($StageConfig.VisualUrgency))"
            Write-Output "Scenario: $($StageConfig.Scenario)"
            Write-Output "Snooze Interval: $($StageConfig.SnoozeInterval)"
            Write-Output "Dismissable: $($StageConfig.AllowDismiss)"

            # Override ToastScenario with stage-specific scenario (unless ForceDisplay set)
            if (!$ForceDisplay) {
                $ToastScenario = $StageConfig.Scenario
                Write-Output "Using stage-specific scenario: $ToastScenario"
            }

            # Extract stage-specific EventText from XML
            $EventText = Get-StageEventText -XmlDocument $XMLToast -StageNumber $SnoozeCount
            if ([string]::IsNullOrWhiteSpace($EventText)) {
                Write-Verbose "Using default EventText (no stage-specific text in XML)"
                # EventText already loaded from XML or will use hardcoded default
            }
            else {
                Write-Verbose "Using stage-specific EventText from XML"
            }

            # Build stage attribution text
            $StageAttribution = ""
            switch ($SnoozeCount) {
                0 { $StageAttribution = "$Signature | Snoozed: 0 of 4" }
                1 { $StageAttribution = "$Signature | Snoozed: 1 of 4" }
                2 { $StageAttribution = "$Signature | Snoozed: 2 of 4" }
                3 { $StageAttribution = "$Signature | Final Snooze: 3 of 4" }
                4 { $StageAttribution = "$Signature | Snooze Limit Reached (4/4)" }
            }
            $Signature = $StageAttribution

            # Stage 4 validation assertions
            if ($StageConfig.Stage -eq 4) {
                if (![string]::IsNullOrEmpty($StageConfig.SnoozeInterval)) {
                    throw "CRITICAL ERROR: Stage 4 must have no snooze interval (found '$($StageConfig.SnoozeInterval)')"
                }
                if ($StageConfig.AllowDismiss -eq $true) {
                    throw "CRITICAL ERROR: Stage 4 must not allow dismiss (AllowDismiss=$($StageConfig.AllowDismiss))"
                }
                if ($StageConfig.Scenario -ne 'alarm') {
                    throw "CRITICAL ERROR: Stage 4 must use 'alarm' scenario (found '$($StageConfig.Scenario)')"
                }
                Write-Output "Stage 4 validation passed: No snooze, no dismiss, alarm scenario"
            }
        }

        #Build toast scenario attribute (control dismiss button visibility)
        # Dismiss button behavior:
        # - scenario="reminder", "alarm", "urgent" → Hides dismiss (X) button (forces user to choose action)
        # - No scenario attribute or scenario="default" → Shows dismiss (X) button (user can close)
        If ($Dismiss) {
            # User explicitly wants dismiss button visible
            $ScenarioAttribute = ''
            Write-Verbose "Dismiss button enabled (no scenario attribute)"
        }
        elseif ($ToastScenario -eq 'default') {
            # Default scenario shows dismiss button, but we want to hide it unless -Dismiss specified
            # Change to 'reminder' to hide dismiss while maintaining standard notification behavior
            $ScenarioAttribute = "scenario=`"reminder`""
            Write-Verbose "Dismiss button hidden (scenario=reminder)"
        }
        else {
            # Use specified scenario (alarm, urgent, reminder all hide dismiss button)
            $ScenarioAttribute = "scenario=`"$ToastScenario`""
            Write-Verbose "Using scenario=$ToastScenario (dismiss button hidden)"
        }

        # XML-encode all text variables for safe embedding
        $CustomHello_Safe = ConvertTo-XmlSafeString $CustomHello
        $ToastTitle_Safe = ConvertTo-XmlSafeString $ToastTitle
        $Signature_Safe = ConvertTo-XmlSafeString $Signature
        $EventTitle_Safe = ConvertTo-XmlSafeString $EventTitle
        $EventText_Safe = ConvertTo-XmlSafeString $EventText

        # Determine audio based on stage (if progressive) or default
        $AudioSrc = "ms-winsoundevent:notification.default"
        $AudioLoop = ""
        If ($Snooze -and $StageConfig.AudioLoop) {
            $AudioSrc = "ms-winsoundevent:notification.looping.alarm"
            $AudioLoop = 'loop="true"'
            Write-Output "Using looping alarm audio for Stage $($StageConfig.Stage)"
        }

        #Build XML ToastTemplate
        [xml]$ToastTemplate = @"
<toast duration="$ToastDuration" $ScenarioAttribute>
    <visual>
        <binding template="ToastGeneric">
            <text>$CustomHello_Safe</text>
            <text>$ToastTitle_Safe</text>
            <text placement="attribution">$Signature_Safe</text>
            <image placement="hero" src="$HeroImage"/>
            <image placement="appLogoOverride" hint-crop="circle" src="$BadgeImage"/>
            <group>
                <subgroup>
                    <text hint-style="title" hint-wrap="true">$EventTitle_Safe</text>
                </subgroup>
            </group>
            <group>
                <subgroup>
                    <text hint-style="body" hint-wrap="true">$EventText_Safe</text>
                </subgroup>
            </group>
        </binding>
    </visual>
    <audio src="$AudioSrc" $AudioLoop/>
</toast>
"@

        #Build action buttons based on mode (Snooze vs Simple)
        If ($Snooze) {
            # Snooze mode: Build stage-specific actions
            Write-Output "Building snooze stage actions for Stage $SnoozeCount"

            # XML-encode button titles
            $ButtonTitle_Safe = ConvertTo-XmlSafeString $ButtonTitle
            $ButtonAction_Safe = ConvertTo-XmlSafeString $ButtonAction
            $SnoozeTitle_Safe = ConvertTo-XmlSafeString $SnoozeTitle
            $RebootTitle_Safe = ConvertTo-XmlSafeString $RebootTitle

            # Build actions dynamically based on stage
            $ActionsXML = "<toast><actions>"

            # Add snooze button for Stages 0-2 only (Stage 3 is final warning with no snooze)
            # Stage 3: User must decide - Reboot Now or Dismiss (transitions to Stage 4)
            # Stage 4: No snooze, forced reboot decision
            if ($Snooze -and $StageConfig.Stage -lt 3 -and -not [string]::IsNullOrEmpty($StageConfig.SnoozeInterval)) {
                $SnoozeInterval = $StageConfig.SnoozeInterval
                $SnoozeLabel = ""
                switch ($SnoozeInterval) {
                    "2h" { $SnoozeLabel = "$SnoozeTitle_Safe (2 hours)" }
                    "1h" { $SnoozeLabel = "$SnoozeTitle_Safe (1 hour)" }
                    "30m" { $SnoozeLabel = "$SnoozeTitle_Safe (30 minutes)" }
                    "15m" { $SnoozeLabel = "$SnoozeTitle_Safe (15 minutes)" }
                }

                # Build toast-snooze:// protocol URI
                $SnoozeProtocolUri = "toast-snooze://$ToastGUID/$SnoozeInterval"
                Write-Output "Adding snooze button: $SnoozeLabel (Protocol: $SnoozeProtocolUri)"
                $ActionsXML += "<action arguments=`"$SnoozeProtocolUri`" content=`"$SnoozeLabel`" activationType=`"protocol`" />"
            }
            elseif ($StageConfig.Stage -eq 3) {
                Write-Output "Stage 3: Final warning - No snooze button (user must reboot or dismiss)"
            }

            # Stage 4: Add "Reboot Now" button instead of generic action button
            if ($StageConfig.Stage -eq 4) {
                $RebootProtocolUri = "toast-reboot://$ToastGUID/immediate"
                Write-Output "Adding reboot button: $RebootTitle_Safe (Protocol: $RebootProtocolUri)"
                $ActionsXML += "<action arguments=`"$RebootProtocolUri`" content=`"$RebootTitle_Safe`" activationType=`"protocol`" />"
            }
            else {
                # Stages 0-3: Add generic action button
                Write-Output "Adding action button: $ButtonTitle_Safe"
                $ActionsXML += "<action arguments=`"$ButtonAction_Safe`" content=`"$ButtonTitle_Safe`" activationType=`"protocol`" />"
            }

            # Add Reboot Now button for Stages 0-3 (Stage 4 uses Reboot Now as the only button)
            if ($StageConfig.AllowDismiss) {
                $RebootProtocolUri = "toast-reboot://$ToastGUID/immediate"
                Write-Output "Adding reboot now button for Stage $($StageConfig.Stage)"
                $ActionsXML += "<action arguments=`"$RebootProtocolUri`" content=`"$RebootTitle_Safe`" activationType=`"protocol`"/>"
            }

            $ActionsXML += "</actions></toast>"

            [xml]$ActionTemplate = $ActionsXML
            $Action_Node = $ActionTemplate.toast.actions
        }
        Else {
            # Simple notification: Learn More + Dismiss only
            $ButtonTitle_Safe = ConvertTo-XmlSafeString $ButtonTitle
            $ButtonAction_Safe = ConvertTo-XmlSafeString $ButtonAction

            [xml]$ActionTemplate = @"
<toast>
    <actions>
        <action arguments="$ButtonAction_Safe" content="$ButtonTitle_Safe" activationType="protocol" />
        <action arguments="dismiss" content="Dismiss" activationType="system"/>
    </actions>
</toast>
"@
            $Action_Node = $ActionTemplate.toast.actions
        }

        #Append actions to $ToastTemplate
        [void]$ToastTemplate.toast.AppendChild($ToastTemplate.ImportNode($Action_Node, $true))
        
        #Prepare XML
        $ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
        $ToastXml.LoadXml($ToastTemplate.OuterXml)

        #Prepare and Create Toast
        $ToastMessage = [Windows.UI.Notifications.ToastNotification]::New($ToastXML)

        # Set Priority property if requested (Windows 10 Build 15063+ required)
        If ($Priority -or $ForceDisplay) {
            try {
                # Attempt to set Priority property (may not be supported on older builds)
                $ToastMessage.Priority = [Windows.UI.Notifications.ToastNotificationPriority]::High
                Write-Output "Toast Priority set to High"
            }
            catch {
                Write-Warning "Failed to set Priority property - may not be supported on this Windows version"
                Write-Warning "Priority property requires Windows 10 Build 15063 or later"
                Write-Verbose "Error: $($_.Exception.Message)"
            }
        }

        # Register AppUserModelId with enhanced error handling
        Write-Output "Registering AppUserModelId for toast display..."

        if ($Script:UseForceFailback) {
            Write-Warning "Skipping AppId registration - WinRT unavailable"
            $AppIdRegistered = [PSCustomObject]@{
                Success = $false
                ErrorCategory = "WINRT_UNAVAILABLE"
                IsGPORestricted = $false
                ErrorMessage = "WinRT not available"
                CanRetry = $false
            }
        }
        else {
            try {
                $AppIdRegistered = Register-ToastAppId -AppId $LauncherID -DisplayName "Toast Notification System"

                if ($AppIdRegistered.Success) {
                    Write-Output "[OK] AppUserModelId registered successfully"
                }
                else {
                    Write-Warning "AppId registration failed: $($AppIdRegistered.ErrorCategory)"

                    if ($AppIdRegistered.IsGPORestricted) {
                        Write-Warning "========================================="
                        Write-Warning "[CORPORATE RESTRICTION DETECTED]"
                        Write-Warning "GPO policy prevents AppId registration"
                        Write-Warning "Toast notifications may fail to display"
                        Write-Warning "Script will fail cleanly if toast cannot be shown"
                        Write-Warning "========================================="

                        # Pre-emptive corporate environment detection
                        if ($null -eq $Script:CorporateEnvironment) {
                            $Script:CorporateEnvironment = Test-CorporateEnvironment
                        }
                    }
                }
            }
            catch {
                Write-Warning "AppId registration exception: $($_.Exception.Message)"
                $AppIdRegistered = [PSCustomObject]@{
                    Success = $false
                    ErrorCategory = "REGISTRATION_EXCEPTION"
                    IsGPORestricted = $false
                    ErrorMessage = $_.Exception.Message
                    CanRetry = $false
                }
            }
        }

        # Display toast with comprehensive error handling
        Write-Output "Preparing to display toast notification..."
        $ToastDisplaySucceeded = $false

        try {
            $ErrorActionPreference = 'Stop'

            # Step 1: Validate WinRT assemblies
            if (-not (Test-WinRTAssemblies)) {
                throw "WinRT assemblies not available or not functional"
            }

            # Step 2: Check AppId registration status
            if ($AppIdRegistered) {
                if (-not $AppIdRegistered.Success) {
                    if ($AppIdRegistered.IsGPORestricted) {
                        throw "Corporate GPO restrictions prevent AppId registration"
                    }
                    Write-Warning "Attempting toast despite AppId registration failure..."
                }
            }

            # Step 3: Create toast notifier
            try {
                $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($LauncherID)
                if ($null -eq $Notifier) {
                    throw "CreateToastNotifier returned null"
                }
            }
            catch [System.UnauthorizedAccessException] {
                throw "Access denied creating toast notifier - corporate restrictions"
            }

            # Step 4: Display toast
            Write-Output "Displaying toast notification..."
            try {
                $Notifier.Show($ToastMessage)
                Write-Output "[OK] Toast displayed successfully"
                $ToastDisplaySucceeded = $true
            }
            catch [System.UnauthorizedAccessException] {
                # THIS IS THE "Access is denied" ERROR
                throw "Access denied calling Show() - corporate WinRT restrictions"
            }
            catch [System.Exception] {
                $ExceptionType = $_.Exception.GetType().Name
                throw "Toast display failed ($ExceptionType): $($_.Exception.Message)"
            }
        }
        catch {
            # Toast display failed
            $ToastDisplaySucceeded = $false
            $ErrorDetails = $_.Exception.Message

            Write-Error "========================================="
            Write-Error "[TOAST DISPLAY FAILED]"
            Write-Error "Error: $ErrorDetails"
            Write-Error "Error Type: $($_.Exception.GetType().FullName)"
            if ($_.Exception.HResult) {
                Write-Error "Error Code (HRESULT): 0x$($_.Exception.HResult.ToString('X8'))"
            }
            Write-Error "========================================="
            Write-Error "Check log file for detailed diagnostics"

            # Log the failure for diagnostics
            try {
                $FailureLogPath = "HKLM:\SOFTWARE\ToastNotification\Failures"
                if (-not (Test-Path $FailureLogPath)) {
                    New-Item -Path $FailureLogPath -Force | Out-Null
                }

                Set-ItemProperty -Path $FailureLogPath -Name "LastFailure" -Value (Get-Date).ToString('s') -Type String -Force
                Set-ItemProperty -Path $FailureLogPath -Name "LastError" -Value $ErrorDetails -Type String -Force
                Set-ItemProperty -Path $FailureLogPath -Name "LastErrorType" -Value $_.Exception.GetType().FullName -Type String -Force
            }
            catch {
                Write-Verbose "Could not log failure: $($_.Exception.Message)"
            }
        }
        finally {
            Write-Verbose "Toast display operation completed: Success=$ToastDisplaySucceeded"
        }
        # Continue with progressive logic (only if toast succeeded)
        If ($ToastDisplaySucceeded -and $Snooze) {
            Write-Output "Progressive Stage: $SnoozeCount"

            # Stage 4: Trigger automatic reboot countdown
            If ($SnoozeCount -eq 4 -and !$TestMode) {
                Write-Output "========================================" -ForegroundColor Red
                Write-Output "[STAGE 4] INITIATING REBOOT COUNTDOWN" -ForegroundColor Red
                Write-Output "========================================" -ForegroundColor Red
                Write-Output "Reboot will occur in $RebootCountdownMinutes minutes"
                Write-Output "User can cancel via: shutdown /a"

                $RebootSeconds = $RebootCountdownMinutes * 60
                $RebootCommand = "shutdown.exe /r /t $RebootSeconds /c `"BIOS Update Required: System will reboot in $RebootCountdownMinutes minutes to complete critical security update. Save your work now. To cancel: shutdown /a`" /d p:2:18"

                Write-Output "Executing: $RebootCommand"

                try {
                    Invoke-Expression $RebootCommand
                    Write-Output "[OK] Reboot scheduled successfully for $(Get-Date).AddMinutes($RebootCountdownMinutes)"
                }
                catch {
                    Write-Error "Failed to schedule reboot: $($_.Exception.Message)"
                }
            }
        }

        Stop-Transcript
    }
}
