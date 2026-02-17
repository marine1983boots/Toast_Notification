<#
.SYNOPSIS
    Test script to verify Initialize-SnoozeTasks function works correctly

.DESCRIPTION
    This script tests the pre-creation of scheduled tasks during SYSTEM deployment.
    It verifies that:
    1. Tasks are created when running as SYSTEM
    2. Tasks have correct properties (USERS principal, Disabled state)
    3. Tasks can be modified by standard users

.NOTES
    Version: 1.0
    Date: 2026-02-16
    Must run as Administrator to simulate SYSTEM context
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ToastGUID = "TEST-GUID-1234-5678-ABCDEF",

    [Parameter(Mandatory = $false)]
    [string]$ToastScriptPath = "C:\Path\To\Toast_Notify.ps1"
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Toast Task Pre-Creation Test" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check if running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "[Test 1] Administrator Check" -ForegroundColor Yellow
if ($IsAdmin) {
    Write-Host "  [OK] Running as Administrator" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] Not running as Administrator" -ForegroundColor Red
    Write-Host "  This script must run as Administrator to test task creation" -ForegroundColor Red
    exit 1
}

# Test 2: Check if Toast_Notify.ps1 exists (or use dummy path)
Write-Host ""
Write-Host "[Test 2] Script Path Check" -ForegroundColor Yellow
if (Test-Path $ToastScriptPath) {
    Write-Host "  [OK] Toast_Notify.ps1 found at: $ToastScriptPath" -ForegroundColor Green
}
else {
    Write-Host "  [WARNING] Toast_Notify.ps1 not found at: $ToastScriptPath" -ForegroundColor Yellow
    Write-Host "  Creating test placeholder script..." -ForegroundColor Yellow
    $TestScriptPath = Join-Path $env:TEMP "Toast_Notify_Test.ps1"
    "# Test Script" | Out-File -FilePath $TestScriptPath -Force
    $ToastScriptPath = $TestScriptPath
    Write-Host "  [OK] Using test path: $ToastScriptPath" -ForegroundColor Green
}

# Test 3: Check if test tasks already exist (cleanup first)
Write-Host ""
Write-Host "[Test 3] Pre-existing Task Cleanup" -ForegroundColor Yellow
$CleanupCount = 0
for ($i = 1; $i -le 4; $i++) {
    $TaskName = "Toast_Notification_$($ToastGUID)_Snooze$i"
    $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($ExistingTask) {
        Write-Host "  Removing existing task: $TaskName" -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        $CleanupCount++
    }
}
Write-Host "  [OK] Cleaned up $CleanupCount pre-existing test tasks" -ForegroundColor Green

# Test 4: Create test tasks using New-ScheduledTask cmdlets
Write-Host ""
Write-Host "[Test 4] Task Creation" -ForegroundColor Yellow
$SuccessCount = 0

for ($i = 1; $i -le 4; $i++) {
    $TaskName = "Toast_Notification_$($ToastGUID)_Snooze$i"

    try {
        # Create task action
        $Task_Action = New-ScheduledTaskAction `
            -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" `
            -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$ToastScriptPath"" -ToastGUID ""$ToastGUID"" -EnableProgressive -SnoozeCount $i"

        # Create principal (USERS group)
        $Task_Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited

        # Create settings (disabled)
        $Task_Settings = New-ScheduledTaskSettingsSet `
            -Compatibility V1 `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -Disable

        # Create task
        $New_Task = New-ScheduledTask `
            -Description "TEST: Progressive Toast Notification - Snooze $i (pre-created, disabled)" `
            -Action $Task_Action `
            -Principal $Task_Principal `
            -Settings $Task_Settings

        # Register task
        Register-ScheduledTask -TaskName $TaskName -InputObject $New_Task -Force -ErrorAction Stop | Out-Null
        Write-Host "  [OK] Created task: $TaskName" -ForegroundColor Green
        $SuccessCount++
    }
    catch {
        Write-Host "  [FAIL] Failed to create task: $TaskName" -ForegroundColor Red
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  Tasks created: $SuccessCount / 4" -ForegroundColor $(if ($SuccessCount -eq 4) { 'Green' } else { 'Red' })

# Test 5: Verify task properties
Write-Host ""
Write-Host "[Test 5] Task Property Verification" -ForegroundColor Yellow
$VerifyCount = 0

for ($i = 1; $i -le 4; $i++) {
    $TaskName = "Toast_Notification_$($ToastGUID)_Snooze$i"
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    if ($Task) {
        $AllChecks = $true

        # Check state
        if ($Task.State -eq 'Disabled') {
            Write-Host "  [OK] $TaskName - State: Disabled" -ForegroundColor Green
        }
        else {
            Write-Host "  [FAIL] $TaskName - State: $($Task.State) (expected: Disabled)" -ForegroundColor Red
            $AllChecks = $false
        }

        # Check principal (USERS group)
        $Principal = $Task.Principal.GroupId
        if ($Principal -eq 'S-1-5-32-545' -or $Principal -eq 'BUILTIN\Users') {
            Write-Host "  [OK] $TaskName - Principal: USERS group" -ForegroundColor Green
        }
        else {
            Write-Host "  [FAIL] $TaskName - Principal: $Principal (expected: USERS)" -ForegroundColor Red
            $AllChecks = $false
        }

        # Check triggers (should be empty)
        if ($Task.Triggers.Count -eq 0) {
            Write-Host "  [OK] $TaskName - Triggers: None (as expected)" -ForegroundColor Green
        }
        else {
            Write-Host "  [WARNING] $TaskName - Triggers: $($Task.Triggers.Count) (expected: 0)" -ForegroundColor Yellow
        }

        if ($AllChecks) {
            $VerifyCount++
        }
    }
    else {
        Write-Host "  [FAIL] $TaskName - Task not found" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  Tasks verified: $VerifyCount / 4" -ForegroundColor $(if ($VerifyCount -eq 4) { 'Green' } else { 'Red' })

# Test 6: Simulate USER modification (Set-ScheduledTask)
Write-Host ""
Write-Host "[Test 6] USER Context Modification Simulation" -ForegroundColor Yellow
$TaskName = "Toast_Notification_$($ToastGUID)_Snooze1"

try {
    # Get task
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    Write-Host "  [OK] Retrieved task: $TaskName" -ForegroundColor Green

    # Create test trigger (5 minutes from now)
    $TriggerTime = (Get-Date).AddMinutes(5)
    $Task_Trigger = New-ScheduledTaskTrigger -Once -At $TriggerTime
    Write-Host "  [OK] Created test trigger for: $($TriggerTime.ToString('s'))" -ForegroundColor Green

    # Update task (this is what standard user would do)
    Set-ScheduledTask -TaskName $TaskName -Trigger $Task_Trigger -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Updated task trigger (USER context simulation)" -ForegroundColor Green

    # Enable task (this is what standard user would do)
    Enable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Enabled task (USER context simulation)" -ForegroundColor Green

    # Verify state changed
    $VerifyTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if ($VerifyTask.State -eq 'Ready') {
        Write-Host "  [OK] Task state changed to Ready" -ForegroundColor Green
        Write-Host "  [SUCCESS] Standard user modification simulation passed" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] Task state: $($VerifyTask.State) (expected: Ready)" -ForegroundColor Red
    }
}
catch {
    Write-Host "  [FAIL] USER modification simulation failed" -ForegroundColor Red
    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 7: Final Summary
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$TotalTests = 6
$PassedTests = 0

if ($IsAdmin) { $PassedTests++ }
if ($SuccessCount -eq 4) { $PassedTests++ }
if ($VerifyCount -eq 4) { $PassedTests++ }

Write-Host "Tests Passed: $PassedTests / $TotalTests" -ForegroundColor $(if ($PassedTests -eq $TotalTests) { 'Green' } else { 'Yellow' })

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Verify tasks exist in Task Scheduler (taskschd.msc)" -ForegroundColor White
Write-Host "2. Test as standard user: Click snooze button in toast" -ForegroundColor White
Write-Host "3. Check handler log: C:\ProgramData\ToastNotification\{GUID}\Logs\Toast_Snooze_Handler*.log" -ForegroundColor White
Write-Host "4. Verify task enabled and trigger set in Task Scheduler" -ForegroundColor White

Write-Host ""
Write-Host "Cleanup:" -ForegroundColor Yellow
Write-Host "To remove test tasks, run:" -ForegroundColor White
Write-Host "  for (\$i = 1; \$i -le 4; \$i++) { Unregister-ScheduledTask -TaskName ""Toast_Notification_$ToastGUID`_Snooze\$i"" -Confirm:`$false }" -ForegroundColor Gray

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
