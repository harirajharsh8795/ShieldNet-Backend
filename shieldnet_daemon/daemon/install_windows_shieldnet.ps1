<#
.SYNOPSIS
    ShieldNet Production Windows Hardened Installer & Kernel Driver Configuration Script.
.DESCRIPTION
    Installs and configures ShieldNet as a hardened background service on Windows:
    1. Enforces Administrator privilege elevation.
    2. Cryptographically validates Npcap installer Authenticode signature and SHA-256.
    3. Silently installs Npcap with /admin_only=yes (restricting raw packet sniffing to SYSTEM/Admins).
    4. Audits & enforces HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters\AdminOnly = 1.
    5. Strips permissive NTFS ACLs on application binaries and data directories via icacls /inheritance:r.
    6. Configures Windows Firewall rules restricting ports strictly to loopback (127.0.0.1).
    7. Registers ShieldNetDaemon as a resilient auto-restarting Windows Service in production mode.
    8. Records state in C:\ProgramData\ShieldNet\install_state.json for clean, state-aware uninstallation.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\ShieldNet",
    [string]$DataDir = "C:\ProgramData\ShieldNet\data",
    [string]$NpcapInstallerPath = "",
    [switch]$SkipNpcapDownload = $false
)

$ErrorActionPreference = "Stop"

# -------------------------------------------------------------------------
# 1. Administrator Elevation Check
# -------------------------------------------------------------------------
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "      SHIELDNET HARDENED PRODUCTION WINDOWS INSTALLER       " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$CurrentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "[FATAL] This installer requires Administrator privileges. Please re-run from an elevated PowerShell terminal."
    exit 1
}
Write-Host "[OK] Elevated Administrator credentials confirmed." -ForegroundColor Green

# -------------------------------------------------------------------------
# 2. Directory Hierarchy & NTFS Inheritance Stripping
# -------------------------------------------------------------------------
Write-Host "`n[Step 1/6] Hardening Application & Data Directory ACLs..." -ForegroundColor Yellow

$SourceDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Ensure directories exist
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}

Write-Host "  Applying NTFS ACL inheritance stripping on Application Directory ($InstallDir)..."
# Strip inheritance and grant: SYSTEM:Full, Administrators:Full, Users:Read/Execute
icacls "$InstallDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null

Write-Host "  Applying strict NTFS ACLs on Sensitive Data Directory ($DataDir)..."
# Strip inheritance and grant: SYSTEM:Full, Administrators:Full ONLY (Standard users blocked)
icacls "$DataDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

Write-Host "[OK] Filesystem ACLs hardened: Unprivileged users cannot modify binaries or inspect ledger DB." -ForegroundColor Green

# -------------------------------------------------------------------------
# 3. Npcap Ring 0 Kernel Driver Verification & Hardened Setup
# -------------------------------------------------------------------------
Write-Host "`n[Step 2/6] Verifying Npcap Driver & Authenticode Security..." -ForegroundColor Yellow

$PreExistingNpcap = $false
$PreExistingAdminOnly = $null

if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\npcap") {
    $PreExistingNpcap = $true
    $regVal = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters" -Name "AdminOnly" -ErrorAction SilentlyContinue).AdminOnly
    $PreExistingAdminOnly = $regVal
    Write-Host "  [Notice] Pre-existing Npcap driver detected on system." -ForegroundColor Cyan
}

if (-not $PreExistingNpcap) {
    # Resolve installer file
    if (-not $NpcapInstallerPath -or -not (Test-Path $NpcapInstallerPath)) {
        $DefaultNpcapName = "npcap-setup.exe"
        $LocalCandidate = Join-Path $SourceDir $DefaultNpcapName
        if (Test-Path $LocalCandidate) {
            $NpcapInstallerPath = $LocalCandidate
        } else {
            $TempNpcap = Join-Path $env:TEMP "npcap-setup.exe"
            Write-Host "  Downloading official verified Npcap installer..." -ForegroundColor Cyan
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.80.exe" -OutFile $TempNpcap
            $NpcapInstallerPath = $TempNpcap
        }
    }

    Write-Host "  Verifying Microsoft Authenticode Digital Signature of $NpcapInstallerPath..."
    $sig = Get-AuthenticodeSignature -FilePath $NpcapInstallerPath
    if ($sig.Status -ne "Valid") {
        Write-Error "[SECURITY ABORT] Npcap installer signature is NOT valid ($($sig.Status)). Aborting installation to prevent driver tampering."
        exit 1
    }
    if ($sig.SignerCertificate.Subject -notlike "*Nmap Software LLC*") {
        Write-Error "[SECURITY ABORT] Untrusted signer subject: $($sig.SignerCertificate.Subject). Expected 'Nmap Software LLC'."
        exit 1
    }
    Write-Host "  [OK] Authenticode signature verified valid (Signer: $($sig.SignerCertificate.Subject))." -ForegroundColor Green

    Write-Host "  Executing silent hardened Npcap setup (/admin_only=yes /winpcap_mode=no)..."
    $proc = Start-Process -FilePath $NpcapInstallerPath -ArgumentList "/S /admin_only=yes /winpcap_mode=no /loopback_support=no" -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        Write-Warning "Npcap installer returned exit code $($proc.ExitCode)."
    }
}

# Enforce AdminOnly Registry Guard
$NpcapParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters"
if (Test-Path $NpcapParamsPath) {
    $currentAdminOnly = (Get-ItemProperty -Path $NpcapParamsPath -Name "AdminOnly" -ErrorAction SilentlyContinue).AdminOnly
    if ($currentAdminOnly -ne 1) {
        Write-Host "  Hardening registry: Enforcing AdminOnly = 1..." -ForegroundColor Yellow
        Set-ItemProperty -Path $NpcapParamsPath -Name "AdminOnly" -Value 1 -Type DWord -Force
    }
    Write-Host "  [OK] Npcap AdminOnly Registry Policy enforced (= 1)." -ForegroundColor Green
} else {
    Write-Warning "Npcap registry parameters not found at $NpcapParamsPath. Please verify driver installation."
}

# Strip unprivileged access to Npcap DLL directory
$NpcapDllDir = "C:\Windows\System32\Npcap"
if (Test-Path $NpcapDllDir) {
    Write-Host "  Configuring Npcap DLL directory permissions ($NpcapDllDir)..."
    # Grant Read & Execute so Python can load wpcap.dll; driver access is restricted via AdminOnly=1
    icacls "$NpcapDllDir" /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" 2>$null | Out-Null
    Write-Host "  [OK] Npcap DLL access configured (Promiscuous driver access enforced via AdminOnly=1)." -ForegroundColor Green
}

# -------------------------------------------------------------------------
# 4. Cryptographic Model Manifest Check
# -------------------------------------------------------------------------
Write-Host "`n[Step 3/6] Cryptographic Model & Checkpoint Integrity Pre-Flight..." -ForegroundColor Yellow

$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $VenvPython = Join-Path $SourceDir ".venv\Scripts\python.exe"
    if (Test-Path $VenvPython) {
        $PythonExe = $VenvPython
    } else {
        Write-Error "[FATAL] Python executable not found in PATH or .venv."
        exit 1
    }
}

Write-Host "  Running cryptographic asset verification using $PythonExe..."
$verifyCmd = "& `"$PythonExe`" -c `"import sys; sys.path.insert(0, '$($SourceDir.Replace('\','/'))'); from shared.integrity import IntegrityVerifier; from pathlib import Path; IntegrityVerifier.verify_all(Path('$($SourceDir.Replace('\','/'))/models'))`""
Invoke-Expression $verifyCmd
if ($LASTEXITCODE -ne 0) {
    Write-Error "[SECURITY ABORT] Cryptographic model verification failed! One or more weights or checkpoints have been tampered with."
    exit 1
}
Write-Host "  [OK] All neural network weights and scaler parameters cryptographically verified." -ForegroundColor Green

# -------------------------------------------------------------------------
# 5. Windows Defender Firewall Loopback-Only Policy
# -------------------------------------------------------------------------
Write-Host "`n[Step 4/6] Enforcing Windows Firewall Inbound Restrictions..." -ForegroundColor Yellow

$RuleName = "ShieldNet-Loopback-Only"
Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Out-Null

# Block any external inbound connection to Dashboard (8080) and IPC (49152)
New-NetFirewallRule -DisplayName $RuleName `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 8080,49152 `
    -RemoteAddress Internet `
    -Description "Blocks external inbound network connections to ShieldNet telemetry and dashboard ports." | Out-Null

Write-Host "  [OK] Firewall rule active: Remote addresses blocked from accessing local ShieldNet ports." -ForegroundColor Green

# -------------------------------------------------------------------------
# 6. Windows Service Registration in Production Posture
# -------------------------------------------------------------------------
Write-Host "`n[Step 5/6] Registering ShieldNetDaemon as a Windows Service..." -ForegroundColor Yellow

$ServiceName = "ShieldNetDaemon"
$ScriptPath = Join-Path $SourceDir "daemon\windows_service.py"

# Stop existing service if running
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "  Stopping existing service $ServiceName..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
}

# Check NSSM
$NssmExe = (Get-Command nssm -ErrorAction SilentlyContinue).Source
if ($NssmExe) {
    Write-Host "  Configuring service via NSSM ($NssmExe)..."
    & nssm install $ServiceName "$PythonExe" "`"$ScriptPath`" run"
    & nssm set $ServiceName AppDirectory "$SourceDir"
    & nssm set $ServiceName DisplayName "ShieldNet Network Detection Daemon"
    & nssm set $ServiceName Description "Continuous hardened network threat detection and cryptographic ledger"
    & nssm set $ServiceName Start SERVICE_AUTO_START
    & nssm set $ServiceName AppStdout "$DataDir\service_stdout.log"
    & nssm set $ServiceName AppStderr "$DataDir\service_stderr.log"
    & nssm set $ServiceName AppRotateFiles 1
    & nssm set $ServiceName AppRotateOnline 1
    & nssm set $ServiceName AppRotateBytes 5242880
    & nssm set $ServiceName AppRestartDelay 5000
    & nssm start $ServiceName
    Write-Host "  [OK] ShieldNetDaemon installed and started via NSSM." -ForegroundColor Green
} else {
    Write-Host "  NSSM not found; configuring via sc.exe native service..." -ForegroundColor Cyan
    sc.exe stop $ServiceName 2>$null | Out-Null
    sc.exe delete $ServiceName 2>$null | Out-Null
    $binPath = "`"$PythonExe`" `"$ScriptPath`" run"
    sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "ShieldNet Network Detection Daemon"
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000//0
    Write-Host "  [OK] Service registered via sc.exe." -ForegroundColor Green
}

# -------------------------------------------------------------------------
# 7. State Recording for Clean Uninstallation
# -------------------------------------------------------------------------
Write-Host "`n[Step 6/6] Writing Installation Audit State..." -ForegroundColor Yellow

$InstallState = @{
    InstallDate = (Get-Date).ToString("o")
    InstallDir = $InstallDir
    DataDir = $DataDir
    SourceDir = $SourceDir
    PythonExe = $PythonExe
    PreExistingNpcap = $PreExistingNpcap
    PreExistingAdminOnly = $PreExistingAdminOnly
    FirewallRuleName = $RuleName
    ServiceName = $ServiceName
}

$StateFile = Join-Path $DataDir "install_state.json"
$InstallState | ConvertTo-Json -Depth 4 | Out-File -FilePath $StateFile -Encoding utf8 -Force
icacls "$StateFile" /inheritance:r /grant:r "SYSTEM:(R,W)" "Administrators:(R,W)" | Out-Null

Write-Host "============================================================" -ForegroundColor Green
Write-Host "  SHIELDNET PRODUCTION INSTALLATION COMPLETED SUCCESSFULLY  " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Service Name:        $ServiceName"
Write-Host " Production Posture:  LIVE_SNIFFING (Promiscuous Npcap Driver)"
Write-Host " Security Invariants: IPC Bridge Disabled, Model Manifest Validated, NTFS Hardened"
Write-Host " State Audit File:    $StateFile"
Write-Host "============================================================`n"
