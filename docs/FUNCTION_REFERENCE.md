# Toast Notification System - Function Reference

**Version:** 2.4
**Last Updated:** 2026-02-16

This document provides detailed reference information for internal functions used in the Toast Notification System. These functions support registry state management, permission handling, folder organization, and cleanup operations.

---

## Table of Contents

1. [Registry Management Functions](#registry-management-functions)
   - [Initialize-ToastRegistry](#initialize-toastregistry)
   - [Get-ToastState](#get-toaststate)
   - [Set-ToastState](#set-toaststate)
   - [Grant-RegistryPermissions](#grant-registrypermissions)
2. [File System Functions](#file-system-functions)
   - [Initialize-ToastFolderStructure](#initialize-toastfolderstructure)
   - [Remove-StaleToastFolders](#remove-staletoastfolders)
3. [Helper Functions](#helper-functions)
   - [ConvertTo-XmlSafeString](#convertto-xmlsafestring)
   - [Get-StageDetails](#get-stagedetails)
   - [Get-StageEventText](#get-stageeventtext)

---

## Registry Management Functions

### Initialize-ToastRegistry

Creates the registry structure for toast state persistence.

**Syntax:**
```powershell
Initialize-ToastRegistry
    -ToastGUID <String>
    [-RegistryHive <String>]
    [-RegistryPath <String>]
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| ToastGUID | String | Yes | - | Unique identifier for this toast instance (GUID format) |
| RegistryHive | String | No | HKLM | Registry hive to use: HKLM, HKCU, or Custom |
| RegistryPath | String | No | SOFTWARE\ToastNotification | Registry path under the specified hive |

**Return Value:**

Returns a hashtable with registry information:
```powershell
@{
    Path = "HKLM:\SOFTWARE\ToastNotification\{GUID}"
    Created = $true  # or $false if already existed
}
```

**Examples:**

```powershell
# Example 1: Create registry with default HKLM location
Initialize-ToastRegistry -ToastGUID "ABC-123-DEF"

# Example 2: Create registry in HKCU for per-user state
Initialize-ToastRegistry -ToastGUID "ABC-123-DEF" -RegistryHive HKCU

# Example 3: Custom registry location
Initialize-ToastRegistry `
    -ToastGUID "ABC-123-DEF" `
    -RegistryHive HKLM `
    -RegistryPath "SOFTWARE\CompanyName\Notifications"
```

**Notes:**
- Creates parent path if it doesn't exist
- Initializes SnoozeCount to 0
- Sets LastShown to current timestamp
- In HKLM mode, automatically calls Grant-RegistryPermissions when running as SYSTEM

**Registry Structure Created:**
```
HKLM:\SOFTWARE\ToastNotification\{GUID}\
├── SnoozeCount (DWORD) = 0
├── LastShown (String) = ISO 8601 timestamp
└── LastSnoozeInterval (String) = ""
```

---

### Get-ToastState

Reads current toast state from registry.

**Syntax:**
```powershell
Get-ToastState
    -ToastGUID <String>
    [-RegistryHive <String>]
    [-RegistryPath <String>]
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| ToastGUID | String | Yes | - | Unique identifier for this toast instance |
| RegistryHive | String | No | HKLM | Registry hive to use: HKLM, HKCU, or Custom |
| RegistryPath | String | No | SOFTWARE\ToastNotification | Registry path under the specified hive |

**Return Value:**

Returns a PSCustomObject with state properties:
```powershell
[PSCustomObject]@{
    SnoozeCount = 2
    LastShown = "2026-02-16T14:30:00"
    LastSnoozeInterval = "1h"
    RegistryPath = "HKLM:\SOFTWARE\ToastNotification\ABC-123-DEF"
}
```

Returns `$null` if registry path doesn't exist.

**Examples:**

```powershell
# Example 1: Get state from default HKLM location
$State = Get-ToastState -ToastGUID "ABC-123-DEF"
Write-Output "Current snooze count: $($State.SnoozeCount)"

# Example 2: Get state from HKCU
$State = Get-ToastState -ToastGUID "ABC-123-DEF" -RegistryHive HKCU

# Example 3: Check if state exists
$State = Get-ToastState -ToastGUID "ABC-123-DEF"
if ($null -eq $State) {
    Write-Output "No existing state found - first run"
}
else {
    Write-Output "Found existing state with $($State.SnoozeCount) snoozes"
}
```

**Notes:**
- Returns `$null` if registry path doesn't exist (not an error)
- Use this to check if toast has been shown before
- All timestamps are in ISO 8601 format

---

### Set-ToastState

Updates toast state in registry.

**Syntax:**
```powershell
Set-ToastState
    -ToastGUID <String>
    -SnoozeCount <Int>
    [-LastInterval <String>]
    [-RegistryHive <String>]
    [-RegistryPath <String>]
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| ToastGUID | String | Yes | - | Unique identifier for this toast instance |
| SnoozeCount | Int | Yes | - | Current snooze count (0-4) |
| LastInterval | String | No | "" | Last selected snooze interval: "15m", "30m", "1h", "2h", "4h", "eod" |
| RegistryHive | String | No | HKLM | Registry hive to use: HKLM, HKCU, or Custom |
| RegistryPath | String | No | SOFTWARE\ToastNotification | Registry path under the specified hive |

**Return Value:**

Returns `$true` on success, `$false` on failure.

**Examples:**

```powershell
# Example 1: Update state after snooze
Set-ToastState `
    -ToastGUID "ABC-123-DEF" `
    -SnoozeCount 2 `
    -LastInterval "1h"

# Example 2: Increment snooze count
$State = Get-ToastState -ToastGUID "ABC-123-DEF"
$NewCount = $State.SnoozeCount + 1
Set-ToastState `
    -ToastGUID "ABC-123-DEF" `
    -SnoozeCount $NewCount `
    -LastInterval "30m"

# Example 3: Update state in HKCU
Set-ToastState `
    -ToastGUID "ABC-123-DEF" `
    -SnoozeCount 1 `
    -RegistryHive HKCU
```

**Notes:**
- Automatically updates LastShown to current timestamp
- SnoozeCount is validated to be 0-4 range
- Creates registry path if it doesn't exist
- All write operations are atomic

**Error Handling:**

If running as non-admin user in HKLM mode without proper permissions:
```powershell
try {
    Set-ToastState -ToastGUID $GUID -SnoozeCount 1
}
catch [System.UnauthorizedAccessException] {
    Write-Error "Access Denied - Deploy with Grant-RegistryPermissions or use -RegistryHive HKCU"
}
```

---

### Grant-RegistryPermissions

Grants USERS group write permissions to a specific toast registry path only.

**Syntax:**
```powershell
Grant-RegistryPermissions
    -RegistryPath <String>
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| RegistryPath | String | Yes | - | Full registry path to specific toast instance (must match pattern) |

**Security Validation:**

The function enforces strict path validation to prevent privilege escalation:
- Path MUST match pattern: `^HKLM:\\SOFTWARE\\ToastNotification\\[A-F0-9\-]{1,36}$`
- Only paths under `HKLM:\SOFTWARE\ToastNotification\{GUID}` are allowed
- Parent path `HKLM:\SOFTWARE\ToastNotification` remains protected
- Entire software hive `HKLM:\SOFTWARE` remains protected

**Return Value:**

Returns `$true` on success, `$false` on failure.

**Examples:**

```powershell
# Example 1: Grant permissions to specific toast instance
$RegPath = "HKLM:\SOFTWARE\ToastNotification\ABC-123-DEF-456"
Grant-RegistryPermissions -RegistryPath $RegPath

# Example 2: Automatic grant during initialization (SYSTEM context)
if ($RegistryHive -eq 'HKLM') {
    $Result = Initialize-ToastRegistry -ToastGUID $ToastGUID
    Grant-RegistryPermissions -RegistryPath $Result.Path
}

# Example 3: Verify permissions granted
$RegPath = "HKLM:\SOFTWARE\ToastNotification\ABC-123"
Grant-RegistryPermissions -RegistryPath $RegPath

$Acl = Get-Acl -Path $RegPath
$UserRules = $Acl.Access | Where-Object { $_.IdentityReference -eq "BUILTIN\Users" }
if ($UserRules.RegistryRights -match "FullControl") {
    Write-Output "Permissions granted successfully"
}
```

**Security Scope:**

```
HKLM:\
└── SOFTWARE\                                    [PROTECTED - Admin only]
    ├── Microsoft\                               [PROTECTED - Admin only]
    ├── Other\                                   [PROTECTED - Admin only]
    └── ToastNotification\                       [PROTECTED - Admin only]
        ├── ABC-123-DEF-456\                     [USERS CAN WRITE - This toast only]
        │   ├── SnoozeCount                      [USERS CAN WRITE]
        │   ├── LastShown                        [USERS CAN WRITE]
        │   └── LastSnoozeInterval               [USERS CAN WRITE]
        ├── XYZ-789-GHI-012\                     [PROTECTED - Different toast]
        └── FallbackUsage\                       [PROTECTED - Admin only]
```

**Access Control Rule:**

The function creates the following ACL rule:
- **Identity:** BUILTIN\Users (SID: S-1-5-32-545)
- **Rights:** FullControl
- **Inheritance:** ContainerInherit, ObjectInherit (applies to subkeys under this path)
- **Propagation:** None (does NOT propagate to parent or sibling keys)

**Notes:**
- Only call this function when running as SYSTEM/Administrator
- Automatically called by Initialize-ToastRegistry in HKLM mode
- Verifies parent path permissions remain unchanged after granting
- Required for snooze handler to work in user context with HKLM state

**Troubleshooting:**

```powershell
# Verify permissions were applied correctly
$RegPath = "HKLM:\SOFTWARE\ToastNotification\{GUID}"
$Acl = Get-Acl -Path $RegPath
$Acl.Access | Where-Object { $_.IdentityReference -eq "BUILTIN\Users" } | Format-List

# Expected output:
# RegistryRights     : FullControl
# AccessControlType  : Allow
# IdentityReference  : BUILTIN\Users
# IsInherited        : False
# InheritanceFlags   : ContainerInherit, ObjectInherit
# PropagationFlags   : None
```

---

## File System Functions

### Initialize-ToastFolderStructure

Creates standardized folder structure for toast operations.

**Syntax:**
```powershell
Initialize-ToastFolderStructure
    -BaseDirectory <String>
    -ToastGUID <String>
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| BaseDirectory | String | Yes | - | Root directory for toast file structure |
| ToastGUID | String | Yes | - | Toast instance GUID for unique path |

**Return Value:**

Returns a hashtable with folder paths:
```powershell
@{
    Base    = "C:\ProgramData\ToastNotification\ABC-123-DEF"
    Logs    = "C:\ProgramData\ToastNotification\ABC-123-DEF\Logs"
    Scripts = "C:\ProgramData\ToastNotification\ABC-123-DEF\Scripts"
}
```

**Folder Structure Created:**

```
BaseDirectory\{ToastGUID}\
├── Logs\
│   ├── Toast_Notify_20260216_143022.log
│   ├── Toast_Snooze_Handler_20260216_143530.log
│   └── Toast_Reboot_Handler_20260216_144012.log
├── Scripts\
│   ├── Toast_Snooze_Handler.ps1
│   └── Toast_Reboot_Handler.ps1
└── (future: Registry backups)
```

**Examples:**

```powershell
# Example 1: Create standard folder structure
$FolderStructure = Initialize-ToastFolderStructure `
    -BaseDirectory "C:\ProgramData\ToastNotification" `
    -ToastGUID "ABC-123-DEF"

# Access the paths
Write-Output "Base folder: $($FolderStructure.Base)"
Write-Output "Logs folder: $($FolderStructure.Logs)"
Write-Output "Scripts folder: $($FolderStructure.Scripts)"

# Example 2: Stage handler scripts to Scripts folder
$HandlerSource = "C:\Source\Toast_Snooze_Handler.ps1"
$HandlerDest = Join-Path $FolderStructure.Scripts "Toast_Snooze_Handler.ps1"
Copy-Item -Path $HandlerSource -Destination $HandlerDest -Force

# Example 3: Start logging to Logs folder
$LogPath = Join-Path $FolderStructure.Logs "Toast_Notify_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogPath -Append

# Example 4: Custom base directory
$FolderStructure = Initialize-ToastFolderStructure `
    -BaseDirectory "D:\CustomPath\Toasts" `
    -ToastGUID "XYZ-789"
```

**Notes:**
- Creates all directories if they don't exist
- Uses `-Force` to ensure creation succeeds
- Returns paths as properties for easy access
- All handler scripts should be staged to the Scripts subfolder
- All logs (Toast_Notify, handlers) should go to the Logs subfolder

**Benefits:**
- **Centralized logging:** All toast logs in one location for IT monitoring
- **Isolated scripts:** Working copies of handlers per toast instance
- **Easy cleanup:** Delete entire ToastGUID folder to remove all files
- **Consistent structure:** Same layout across all deployments

---

### Remove-StaleToastFolders

Removes old toast instance folders to prevent bloat.

**Syntax:**
```powershell
Remove-StaleToastFolders
    -BaseDirectory <String>
    [-DaysThreshold <Int>]
```

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| BaseDirectory | String | Yes | - | Root directory containing toast GUID folders |
| DaysThreshold | Int | No | 30 | Remove folders with no file modifications in this many days |

**Return Value:**

Returns count of folders removed.

**Examples:**

```powershell
# Example 1: Remove folders older than 30 days (default)
Remove-StaleToastFolders -BaseDirectory "C:\ProgramData\ToastNotification"

# Example 2: Aggressive cleanup - remove folders older than 7 days
Remove-StaleToastFolders `
    -BaseDirectory "C:\ProgramData\ToastNotification" `
    -DaysThreshold 7

# Example 3: Conservative cleanup - keep folders for 90 days
Remove-StaleToastFolders `
    -BaseDirectory "C:\ProgramData\ToastNotification" `
    -DaysThreshold 90

# Example 4: Cleanup with logging
$Removed = Remove-StaleToastFolders -BaseDirectory "C:\ProgramData\ToastNotification"
Write-Output "Removed $Removed stale toast folders"
```

**How It Works:**

1. Scans `BaseDirectory` for GUID-pattern folders
2. For each folder, finds the most recent file modification time
3. Calculates age: `(Get-Date) - (Most Recent File Modification)`
4. If age > `DaysThreshold`, removes entire folder
5. Returns count of removed folders

**Folder Age Determination:**

Age is based on the MOST RECENT file modification in the folder, not folder creation time. This ensures:
- Active toast instances (recently modified logs) are NOT removed
- Completed toast instances (no recent activity) ARE removed
- User activity (viewing logs) doesn't prevent cleanup

**Notes:**
- Only removes GUID-pattern folders (matches: `^[A-F0-9\-]{1,36}$`)
- Does NOT remove the base directory itself
- Safe to run repeatedly (idempotent operation)
- Automatically called during Initialize-ToastFolderStructure

**Automatic Cleanup:**

Toast_Notify.ps1 automatically calls this function with the `-CleanupDaysThreshold` parameter value:

```powershell
# Called during toast initialization
Remove-StaleToastFolders `
    -BaseDirectory $WorkingDirectory `
    -DaysThreshold $CleanupDaysThreshold  # Default: 30 days
```

**Manual Cleanup:**

To immediately remove all old toast folders:

```powershell
# Remove all toast folders older than 1 day
Remove-StaleToastFolders `
    -BaseDirectory "C:\ProgramData\ToastNotification" `
    -DaysThreshold 1

# Verify cleanup
Get-ChildItem "C:\ProgramData\ToastNotification" | Measure-Object
```

---

## Helper Functions

### ConvertTo-XmlSafeString

Encodes strings for safe XML embedding, preventing XML injection attacks.

**Syntax:**
```powershell
ConvertTo-XmlSafeString -InputString <String>
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| InputString | String | Yes | String to encode for XML |

**Return Value:**

Returns XML-safe encoded string.

**Examples:**

```powershell
# Example 1: Encode user input
$UserInput = "BIOS Update: <Critical> & 'Urgent'"
$SafeString = ConvertTo-XmlSafeString -InputString $UserInput
# Result: "BIOS Update: &lt;Critical&gt; &amp; &apos;Urgent&apos;"

# Example 2: Encode attribute values
$Title = ConvertTo-XmlSafeString -InputString $ToastTitle
$AttributionText = ConvertTo-XmlSafeString -InputString $ToastAttribution
$XML = "<text>$Title</text><text hint-style='caption'>$AttributionText</text>"
```

**Character Encodings:**

| Character | Encoding |
|-----------|----------|
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&apos;` |

---

### Get-StageDetails

Returns configuration for a specific progressive enforcement stage.

**Syntax:**
```powershell
Get-StageDetails -Stage <Int>
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| Stage | Int | Yes | Stage number (0-4) |

**Return Value:**

Returns PSCustomObject with stage configuration:
```powershell
[PSCustomObject]@{
    Stage = 2
    Scenario = "reminder"
    Priority = $false
    AllowDismiss = $true
    SnoozeIntervals = @("15m", "30m", "1h", "2h", "4h", "eod")
    DefaultInterval = "1h"
}
```

**Stage Configurations:**

| Stage | Scenario | Priority | Dismiss | Snooze Intervals | Sound |
|-------|----------|----------|---------|------------------|-------|
| 0 | default | false | true | All | Default |
| 1 | reminder | false | true | All | Default |
| 2 | reminder | false | true | All | Default |
| 3 | urgent | true | true | Limited | Urgent |
| 4 | alarm | true | false | None | Alarm |

---

### Get-StageEventText

Retrieves stage-specific EventText from XML if available.

**Syntax:**
```powershell
Get-StageEventText -XMLContent <XmlDocument> -Stage <Int>
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| XMLContent | XmlDocument | Yes | Loaded XML document |
| Stage | Int | Yes | Stage number (0-4) |

**Return Value:**

Returns event text string for the stage, or empty string if not defined.

**XML Structure:**

```xml
<ToastContent>
    <Stage0>First notification - please take action soon</Stage0>
    <Stage1>Second reminder - action required</Stage1>
    <Stage2>Third reminder - please don't ignore</Stage2>
    <Stage3>Urgent: Action required immediately</Stage3>
    <Stage4>Final warning: System will reboot</Stage4>
</ToastContent>
```

---

## Usage Workflow

### Typical Toast Initialization Workflow

```powershell
# 1. Initialize folder structure
$FolderStructure = Initialize-ToastFolderStructure `
    -BaseDirectory "C:\ProgramData\ToastNotification" `
    -ToastGUID $ToastGUID

# 2. Start logging
$LogPath = Join-Path $FolderStructure.Logs "Toast_Notify_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogPath -Append

# 3. Initialize registry
$RegResult = Initialize-ToastRegistry `
    -ToastGUID $ToastGUID `
    -RegistryHive $RegistryHive `
    -RegistryPath $RegistryPath

# 4. Grant permissions (if HKLM mode and SYSTEM context)
if ($RegistryHive -eq 'HKLM') {
    Grant-RegistryPermissions -RegistryPath $RegResult.Path
}

# 5. Get current state
$State = Get-ToastState `
    -ToastGUID $ToastGUID `
    -RegistryHive $RegistryHive `
    -RegistryPath $RegistryPath

# 6. Determine stage based on snooze count
if ($null -eq $State) {
    $SnoozeCount = 0
}
else {
    $SnoozeCount = $State.SnoozeCount
}

$StageConfig = Get-StageDetails -Stage $SnoozeCount

# 7. Stage handler scripts
$ScriptStagingPath = $FolderStructure.Scripts
Copy-Item -Path "Toast_Snooze_Handler.ps1" -Destination $ScriptStagingPath -Force
Copy-Item -Path "Toast_Reboot_Handler.ps1" -Destination $ScriptStagingPath -Force

# 8. Cleanup old toast folders
Remove-StaleToastFolders `
    -BaseDirectory "C:\ProgramData\ToastNotification" `
    -DaysThreshold 30
```

---

## See Also

- [Technical Documentation](TECHNICAL_DOCUMENTATION_TOAST_v3.0.md) - Complete system documentation
- [Deployment Guide](DEPLOYMENT_GUIDE.md) - Corporate deployment scenarios (Coming Soon)
- [README.md](../README.md) - Quick start guide

---

**Document Version:** 1.0
**Last Updated:** 2026-02-16
**Maintainer:** Toast Notification Development Team
