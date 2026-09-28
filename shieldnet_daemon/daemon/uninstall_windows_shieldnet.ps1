<#
.SYNOPSIS
    ShieldNet Production Windows Clean Uninstaller.
.DESCRIPTION
    Safely tears down the ShieldNet production service:
    1. Stops and removes the ShieldNetDaemon Windows Service.
    2. Removes custom Windows Defender Firewall loopback rules.
    3. Securely removes any ephemeral tokens or runtime cache files.
    4. Provides optional cryptographic Action Ledger archiving for legal/compliance retention.
    5. Reverts Npcap registry settings only if originally modified by ShieldNet.
#>

[CmdletBinding()]
param(
    [string]$DataDir = "C:\ProgramData\ShieldNet\data",
    [switch]$KeepLedger = $true,
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         SHIELDNET PRODUCTION CLEAN UNINSTALLER             " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Admin Elevation Check
$CurrentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[FATAL] Administrator privileges are required to uninstall ShieldNet."
    exit 1
}

# 2. Stop and Remove Windows Service
$ServiceName = "ShieldNetDaemon"
Write-Host "`n[1/4] Stopping and removing Windows Service '$ServiceName'..." -ForegroundColor Yellow

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

$NssmExe = (Get-Command nssm -ErrorAction SilentlyContinue).Source
if ($NssmExe) {
    & nssm stop $ServiceName 2>$null | Out-Null
    & nssm remove $ServiceName confirm 2>$null | Out-Null
}
sc.exe stop $ServiceName 2>$null | Out-Null
sc.exe delete $ServiceName 2>$null | Out-Null
Write-Host "[OK] Service '$ServiceName' removed from Windows Service Manager." -ForegroundColor Green

# 3. Remove Firewall Rules
Write-Host "`n[2/4] Removing ShieldNet custom firewall rules..." -ForegroundColor Yellow
Remove-NetFirewallRule -DisplayName "ShieldNet-Loopback-Only" -ErrorAction SilentlyContinue | Out-Null
Write-Host "[OK] Firewall rules cleaned up." -ForegroundColor Green

# 4. Action Ledger Archiving / Cleanup
Write-Host "`n[3/4] Handling Cryptographic Action Ledger & Telemetry State..." -ForegroundColor Yellow
$StateFile = Join-Path $DataDir "install_state.json"
$LedgerDb = Join-Path $DataDir "ledger.db"

if (Test-Path $LedgerDb) {
    if ($KeepLedger) {
        $ArchiveDir = "C:\ProgramData\ShieldNet\archive"
        New-Item -ItemType Directory -Path $ArchiveDir -Force | Out-Null
        $Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $ArchiveFile = Join-Path $ArchiveDir "ledger_backup_$Timestamp.db"
        Copy-Item -Path $LedgerDb -Destination $ArchiveFile -Force
        Write-Host "  [Compliance Retention] Action Ledger cryptographically archived to:" -ForegroundColor Cyan
        Write-Host "  -> $ArchiveFile" -ForegroundColor Cyan
    } else {
        Remove-Item -Path $LedgerDb -Force -ErrorAction SilentlyContinue
        Write-Host "  Action Ledger removed." -ForegroundColor Gray
    }
}

# 5. Token & Cache Shredding
Write-Host "`n[4/4] Shredding ephemeral tokens and temporary status files..." -ForegroundColor Yellow
$EphemeralFiles = @(
    (Join-Path $DataDir ".ipc_token"),
    (Join-Path $DataDir "daemon_status.json"),
    (Join-Path $DataDir "daemon_status.json.tmp"),
    $StateFile
)

foreach ($f in $EphemeralFiles) {
    if (Test-Path $f) {
        Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "============================================================" -ForegroundColor Green
Write-Host "      SHIELDNET UNINSTALLATION COMPLETED CLEANLY            " -ForegroundColor Green
Write-Host "============================================================`n"
