# Toast Notification System

A PowerShell-based enterprise toast notification system for Windows 10/11 with progressive enforcement, designed for SCCM/Intune deployment.

**Current version:** Toast_Notify.ps1 v2.31
**Production release:** v1.0.0

---

## Overview

Toast_Notify.ps1 displays Windows toast notifications to logged-on users. When deployed as SYSTEM (SCCM/Intune), it creates a scheduled task that fires in the user's interactive session, showing the notification with configurable content from an XML file.

The `-Snooze` switch enables **progressive enforcement** - a 5-stage escalation system that ensures users cannot indefinitely defer critical notifications. Each ignored or snoozed toast advances through stages toward a forced reboot at Stage 4.

---

## Progressive Enforcement Stages

| Stage | Scenario | Snooze Interval | Focus Assist | User Options |
|-------|----------|-----------------|--------------|--------------|
| 0     | alarm    | 4 hours         | Bypassed     | Snooze / Dismiss |
| 1     | alarm    | 2 hours         | Bypassed     | Snooze / Dismiss |
| 2     | alarm    | 1 hour          | Bypassed     | Snooze / Dismiss |
| 3     | urgent   | None            | Bypassed     | Reboot Now / Dismiss |
| 4     | alarm    | None (forced)   | Bypassed     | Reboot Now only |

**Fallback escalation:** If a user ignores a toast entirely (no button press, natural timeout), a fallback scheduled task fires after the stage interval and advances to the next stage. A user who never interacts will escalate from Stage 0 to Stage 4 automatically.

---

## Required Files

```
src/
  Toast_Notify.ps1            # Main script
  Toast_Snooze_Handler.ps1    # Handles Snooze button clicks
  Toast_Reboot_Handler.ps1    # Handles Reboot Now button clicks
  Toast_Dismiss_Handler.ps1   # Handles Dismiss button clicks
  BIOS_Update.xml             # Example XML (replace with your own)
  BadgeImage_HP.jpg           # Badge image (replace with your own)
  HeroImage_BIOS.jpg          # Hero image (replace with your own)
```

All handler scripts and the XML must be in the same directory as `Toast_Notify.ps1` when deployed, or accessible via the paths configured in the XML.

---

## Parameters

### Core Parameters

**.PARAMETER XMLSource**

Name of the XML configuration file. Must be in the same directory as `Toast_Notify.ps1` or a full path.

- Default: `CustomMessage.xml`
- Example: `-XMLSource "BIOS_Update.xml"`

**.PARAMETER Snooze**

Enable progressive enforcement mode. The notification will escalate through Stages 0-4. Without `-Snooze`, a one-time toast is displayed with no escalation.

**.PARAMETER ToastGUID**

Unique identifier for this notification campaign. Used to namespace registry state, scheduled tasks, and log files. Auto-generated if not specified.

- Format: Standard GUID (e.g. `A1B2C3D4-E5F6-7890-ABCD-EF1234567890`)
- Tip: Use a fixed GUID per campaign so state persists across deployments.

**.PARAMETER AppIDName**

Display name shown in the Windows notification system (Action Center, notification history).

- Default: `System IT`
- Max length: 128 characters

**.PARAMETER RebootCountdownMinutes**

Countdown in minutes before automatic reboot at Stage 4.

- Default: `5`
- Range: 1-1440
- The computed reboot time is shown in the Stage 4 toast text.

**.PARAMETER ToastScenario**

Override the toast notification scenario. When using `-Snooze`, the scenario is set automatically per stage - this parameter only applies to non-snooze toasts.

- `alarm` (default): High priority, bypasses Focus Assist
- `urgent`: High priority, bypasses Focus Assist
- `reminder`: Standard priority, suppressed by Focus Assist
- `default`: Standard Windows notification behaviour

**.PARAMETER Dismiss**

Show the dismiss (X) button in the toast notification.

- Default: hidden (forces user to choose an action)
- With `-Dismiss`: user can close without taking action
- Use for informational toasts or testing

**.PARAMETER RegistryHive**

Where toast stage state is stored.

- `HKLM` (default): Machine-wide. All users share state. Requires SYSTEM deployment for permission grant. Best for enforcing machine reboot regardless of user.
- `HKCU`: Per-user state. No permission issues. Best for multi-user machines where each user has independent state.
- `Custom`: Advanced - use with `-RegistryPath`.

**.PARAMETER RegistryPath**

Custom registry path under the selected hive.

- Default: `SOFTWARE\ToastNotification`

**.PARAMETER WorkingDirectory**

Base directory for organized folder structure. Creates `{WorkingDirectory}\{GUID}\Logs\` and `Scripts\` subfolders.

- Default: `C:\ProgramData\ToastNotification`
- All handler logs are written to the `Logs\` subfolder.

**.PARAMETER CleanupDaysThreshold**

Days before stale toast folders are automatically removed.

- Default: `30`
- Range: 1-365

**.PARAMETER ForceDisplay**

Maximum visibility mode. Forces the toast to display even under suppression conditions.

**.PARAMETER Priority**

High priority notification mode.

**.PARAMETER AdvanceStage**

Increments the stage counter before displaying. Used internally by fallback scheduled tasks - do not pass manually.

---

## Deployment

### SCCM / Intune (SYSTEM context)

Deploy as a SYSTEM-context package or script. The script detects it is running as SYSTEM and creates a scheduled task to fire in the logged-on user's interactive session.

**Basic notification (no enforcement):**
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File Toast_Notify.ps1 -XMLSource "CustomMessage.xml"
```

**Progressive enforcement (recommended for reboot campaigns):**
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File Toast_Notify.ps1 `
    -XMLSource "BIOS_Update.xml" `
    -ToastGUID "A1B2C3D4-E5F6-7890-ABCD-EF1234567890" `
    -Snooze `
    -RebootCountdownMinutes 15 `
    -AppIDName "IT Support"
```

**Per-user state (multi-user endpoints):**
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File Toast_Notify.ps1 `
    -XMLSource "BIOS_Update.xml" `
    -Snooze `
    -RegistryHive HKCU
```

### XML Configuration

Copy and edit `examples/CustomMessage.xml` or `src/BIOS_Update.xml`. The XML controls the toast title, body text, images, and action button URL. The `BIOS_Update.xml` demonstrates manufacturer-specific content via `{MANUFACTURER}` token replacement (HP/Lenovo/Default detection via CIM).

---

## Architecture

### State Management

Stage state is stored in the registry at `HKLM:\SOFTWARE\ToastNotification\{GUID}` (or HKCU). The following values are tracked:

| Value | Type | Purpose |
|-------|------|---------|
| SnoozeCount | DWORD | Current stage (0-4) |
| XMLSource | String | XML file path for snooze task chain |
| ToastScenario | String | Scenario for snooze task chain |
| RebootCountdownMinutes | DWORD | Countdown for Stage 4 |

### Scheduled Tasks

When `-Snooze` is used, the following tasks are created:

| Task | Creator | Purpose |
|------|---------|---------|
| `Toast_Notification_{GUID}` | Toast_Notify.ps1 (SYSTEM) | Main notification task |
| `Toast_Notification_{GUID}_{Username}_Snooze{N}` | Toast_Snooze_Handler.ps1 (user) | Next snooze trigger |
| `Toast_Notification_{GUID}_{Username}_Fallback` | Toast_Notify.ps1 (SYSTEM) | Fires if toast ignored |

Snooze tasks are created dynamically in the user's interactive session (no admin rights required). Fallback tasks are created by the SYSTEM context script before the toast is shown, and cancelled by handler scripts when the user takes any action.

### Protocol Handlers

The following custom URI protocols are registered during SYSTEM deployment:

- `toast-dismiss://` - Invoked by the Dismiss button; triggers `Toast_Dismiss_Handler.ps1`

---

## Files Reference

| File | Version | Purpose |
|------|---------|---------|
| `src/Toast_Notify.ps1` | v2.31 | Main notification script |
| `src/Toast_Snooze_Handler.ps1` | v1.11 | Snooze button handler |
| `src/Toast_Reboot_Handler.ps1` | v1.3 | Reboot button handler |
| `src/Toast_Dismiss_Handler.ps1` | v1.1 | Dismiss button handler |
| `src/BIOS_Update.xml` | - | Example XML for BIOS update campaign |
| `src/BadgeImage_HP.jpg` | - | HP badge image (replace as needed) |
| `src/HeroImage_BIOS.jpg` | - | HP hero image (replace as needed) |
| `examples/CustomMessage.xml` | - | Minimal XML template |
| `docs/TECHNICAL_DOCUMENTATION_TOAST_v3.0.md` | v4.1 | Full ISO 9001 technical documentation |
| `docs/IMAGE_CREATION_GUIDE.md` | - | Image size and format requirements |

---

## Requirements

- Windows 10 / Windows 11
- PowerShell 5.1 or later
- SYSTEM context deployment (SCCM / Intune) for progressive enforcement
- No third-party modules required

---

## Troubleshooting

**Toast does not appear:**
- Verify script is running in SYSTEM context (check task manager / event log)
- Check `C:\ProgramData\ToastNotification\{GUID}\Logs\` for script output
- Confirm a user is logged on interactively

**Snooze task not created / Access Denied:**
- Ensure deployment is from SYSTEM context (required for DACL grant)
- Check event log for `Register-ScheduledTask` errors

**Focus Assist suppressing toasts:**
- Stages 0-4 all use `alarm` or `urgent` scenario which bypasses Focus Assist
- If using a non-snooze toast with `-ToastScenario reminder`, this will be suppressed

**Stage not advancing:**
- Check registry `HKLM:\SOFTWARE\ToastNotification\{GUID}` for `SnoozeCount` value
- Verify fallback task exists: `Toast_Notification_{GUID}_{Username}_Fallback`
- See `docs/TECHNICAL_DOCUMENTATION_TOAST_v3.0.md` Section 12.17 for v2.31 fix details

---

## Documentation

Full ISO 9001/27001 compliant technical documentation:
`docs/TECHNICAL_DOCUMENTATION_TOAST_v3.0.md` (v4.1)

Includes architecture, function reference, security assessment, code review records, and full changelog from v2.0 through v2.31.

---

## License & Attribution

Based on [Toast](https://github.com/byteben/Toast) by [Ben Whitmore](https://github.com/byteben) (@byteben), originally released under the GNU General Public License v3.

All modifications released under GPLv3. See LICENSE for full terms.
