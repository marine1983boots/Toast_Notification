<#
.SYNOPSIS
    Registers the toast-reboot:// custom URI protocol handler

.DESCRIPTION
    This script registers the toast-reboot:// protocol in HKEY_CLASSES_ROOT
    so that toast notification reboot buttons can trigger the handler script.

    MUST be run as Administrator (elevated PowerShell).

.NOTES
    Author: System Administrator
    Version: 1.0
    Last Modified: 2026-02-13

    Change Log:
    - 1.0: Initial version - Reboot protocol handler registration

.EXAMPLE
    .\Register-ToastRebootProtocol.ps1

    Registers the toast-reboot:// protocol handler.

.EXAMPLE
    Start-Process 'toast-reboot://TEST-GUID-123'

    Test the registered protocol handler.
#>

[CmdletBinding()]
param()

# Check if running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "This script must be run as Administrator!"
    Write-Error "Right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

Write-Host "[OK] Running as Administrator" -ForegroundColor Green

# Get script directory
$ScriptDir = $PSScriptRoot
$HandlerPath = Join-Path $ScriptDir "Toast_Reboot_Handler.ps1"

# Verify handler script exists
if (-not (Test-Path $HandlerPath)) {
    Write-Error "Handler script not found: $HandlerPath"
    Write-Error "Make sure Toast_Reboot_Handler.ps1 is in the same directory as this script"
    exit 1
}

Write-Host "[OK] Handler script found: $HandlerPath" -ForegroundColor Green

# Register protocol in HKEY_CLASSES_ROOT
Write-Host "`nRegistering toast-reboot:// protocol..." -ForegroundColor Cyan

try {
    # Create protocol key
    $ProtocolKey = "Registry::HKEY_CLASSES_ROOT\toast-reboot"

    Write-Host "  Creating protocol key..." -ForegroundColor Yellow
    New-Item -Path $ProtocolKey -Force | Out-Null

    Set-ItemProperty -Path $ProtocolKey -Name "(Default)" -Value "URL:Toast Reboot Protocol"
    Set-ItemProperty -Path $ProtocolKey -Name "URL Protocol" -Value ""

    Write-Host "  [OK] Protocol key created" -ForegroundColor Green

    # Create command key
    $CommandKey = "$ProtocolKey\shell\open\command"

    Write-Host "  Creating command handler..." -ForegroundColor Yellow
    New-Item -Path $CommandKey -Force | Out-Null

    $CommandValue = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$HandlerPath`" -ProtocolUri `"%1`""
    Set-ItemProperty -Path $CommandKey -Name "(Default)" -Value $CommandValue

    Write-Host "  [OK] Command handler registered" -ForegroundColor Green

    # Verify registration
    Write-Host "`nVerifying registration..." -ForegroundColor Cyan

    $VerifyProtocol = Test-Path $ProtocolKey
    $VerifyCommand = Test-Path $CommandKey

    if ($VerifyProtocol -and $VerifyCommand) {
        Write-Host "[OK] Protocol handler successfully registered!" -ForegroundColor Green
        Write-Host "`nProtocol: toast-reboot://" -ForegroundColor Cyan
        Write-Host "Handler: $HandlerPath" -ForegroundColor Cyan

        # Display test command
        Write-Host "`nTesting protocol invocation..." -ForegroundColor Cyan
        Write-Host "You can test with: Start-Process 'toast-reboot://TEST-GUID-123'" -ForegroundColor Yellow

        Write-Host "`n[SUCCESS] You can now test reboot toast notifications!" -ForegroundColor Green
    }
    else {
        Write-Error "Verification failed - protocol may not be registered correctly"
        exit 1
    }
}
catch {
    Write-Error "Failed to register protocol: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
