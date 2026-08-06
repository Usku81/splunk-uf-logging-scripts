# =============================================================================
# Install-SplunkUF-Windows.ps1
#
# PURPOSE  : Install Splunk Universal Forwarder silently from PowerShell.
#            Two scenarios:
#              1. Windows Workstation / Member Server
#              2. Windows Domain Controller
#
# SOURCE   : https://help.splunk.com/en/splunk-cloud-platform/forward-and-process-data/
#            universal-forwarder-manual/10.2/install-the-universal-forwarder/
#            install-a-windows-universal-forwarder
#
# USAGE    :
#   # Workstation:
#   .\Install-SplunkUF-Windows.ps1 -Scenario Workstation `
#       -MsiPath "C:\Temp\splunkforwarder_x64.msi" `
#       -IndexerHost "splunk-indexer.corp.local" `
#       -AdminPassword "Ch@ng3d!"
#
#   # Domain Controller:
#   .\Install-SplunkUF-Windows.ps1 -Scenario DC `
#       -MsiPath "C:\Temp\splunkforwarder_x64.msi" `
#       -IndexerHost "splunk-indexer.corp.local" `
#       -AdminPassword "Ch@ng3d!" `
#       -SvcUsername "CORP\svc-splunkuf" `
#       -SvcPassword "SvcP@ssw0rd!"
#
# REQUIRES : Run as Administrator. MSI downloaded separately from:
#            https://www.splunk.com/en_us/download/universal-forwarder.html
# =============================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Workstation","DC")]
    [string]$Scenario,

    [Parameter(Mandatory)]
    [string]$MsiPath,                          # Full path to splunkforwarder_x64.msi

    [Parameter(Mandatory)]
    [string]$IndexerHost,                      # Indexer hostname or IP (port defaults to 9997)

    [string]$IndexerPort      = "9997",

    [Parameter(Mandatory)]
    [string]$AdminPassword,                    # Splunk admin user password

    [string]$AdminUsername    = "admin",       # Splunk admin username (default: admin)

    # DC only — domain service account to run the SplunkForwarder service
    [string]$SvcUsername,                      # Format: DOMAIN\username
    [string]$SvcPassword,

    [string]$InstallDir       = "C:\Program Files\SplunkUniversalForwarder",

    # Optional: deployment server (instead of / in addition to direct indexer)
    [string]$DeploymentServer                  # Format: hostname:8089
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Validate MSI ────────────────────────────────────────────────────
if (-not (Test-Path $MsiPath)) {
    Write-Error "MSI not found: $MsiPath`nDownload from: https://www.splunk.com/en_us/download/universal-forwarder.html"
    exit 1
}

# ── Validate DC params ──────────────────────────────────────────────
if ($Scenario -eq "DC" -and (-not $SvcUsername -or -not $SvcPassword)) {
    Write-Error "DC scenario requires -SvcUsername (DOMAIN\user) and -SvcPassword."
    exit 1
}

$Receiver = "${IndexerHost}:${IndexerPort}"

Write-Host ""
Write-Host "  Installing Splunk Universal Forwarder" -ForegroundColor Cyan
Write-Host "  Scenario  : $Scenario"                -ForegroundColor Cyan
Write-Host "  Indexer   : $Receiver"                -ForegroundColor Cyan
Write-Host "  Install   : $InstallDir"              -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════════════════════════════
# SCENARIO 1 — WINDOWS WORKSTATION / MEMBER SERVER
#
# Flags used (source: Splunk docs flag table):
#   USE_LOCAL_SYSTEM=1        — Run as Local System; guarantees access to
#                               Security/System/Application logs and all
#                               operational channels enabled by the prereq
#                               script without needing a service account.
#   PRIVILEGESECURITY=1       — Grants SeSecurityPrivilege so WinEventLog
#                               inputs can collect Security event logs.
#   PRIVILEGEBACKUP=1         — Grants SeBackupPrivilege so file monitor
#                               inputs can read any file regardless of ACL
#                               (required for Sysmon, PS, TaskScheduler etc.)
#   PRIVILEGEIMPERSONATE=1    — Grants SeImpersonatePrivilege so the UF
#                               user can be added to local groups (e.g.
#                               Performance Monitor Users) for WMI/perfmon.
#   GROUPPERFORMANCEMONITORUSERS=1 — Adds UF user to Performance Monitor
#                               Users group; required for WMI inputs.
#   RECEIVING_INDEXER         — Sets outputs at install time (indexer:port).
#   LAUNCHSPLUNK=1            — Start the service immediately after install.
#   SERVICESTARTTYPE=auto     — Start automatically on every reboot.
#   /quiet                    — Silent, no UI prompts.
# ═══════════════════════════════════════════════════════════════════
if ($Scenario -eq "Workstation") {

    $msiArgs = @(
        "/i", "`"$MsiPath`"",
        "INSTALLDIR=`"$InstallDir`"",
        "AGREETOLICENSE=Yes",
        "SPLUNKUSERNAME=$AdminUsername",
        "SPLUNKPASSWORD=$AdminPassword",
        "RECEIVING_INDEXER=`"$Receiver`"",
        "USE_LOCAL_SYSTEM=1",
        "PRIVILEGESECURITY=1",
        "PRIVILEGEBACKUP=1",
        "PRIVILEGEIMPERSONATE=1",
        "GROUPPERFORMANCEMONITORUSERS=1",
        "LAUNCHSPLUNK=1",
        "SERVICESTARTTYPE=auto",
        "/quiet",
        "/l*v", "`"$env:TEMP\splunkuf-install-workstation.log`""
    )

    if ($DeploymentServer) {
        $msiArgs += "DEPLOYMENT_SERVER=`"$DeploymentServer`""
    }

    Write-Host "  Running msiexec (Workstation)..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  msiexec.exe $($msiArgs -join ' ')" -ForegroundColor Gray
    Write-Host ""

    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    $exitCode = $proc.ExitCode

# ═══════════════════════════════════════════════════════════════════
# SCENARIO 2 — DOMAIN CONTROLLER
#
# Additional / changed flags vs Workstation:
#   LOGON_USERNAME / LOGON_PASSWORD — Run the SplunkForwarder service as
#                               a dedicated domain service account instead
#                               of Local System. On a DC, Local System ==
#                               DOMAIN\<DCName>$ which has broad AD rights;
#                               a least-privilege svc account is safer.
#                               The account needs:
#                                 - Log on as a service right
#                                 - Read access to event log channels
#                                 - SeSecurityPrivilege (granted by
#                                   PRIVILEGESECURITY=1 below)
#   ENABLEADMON=1               — Enables Active Directory monitoring inputs
#                               (required for AD change detection on DCs).
#   USE_LOCAL_SYSTEM=0          — Explicitly do NOT use Local System on a DC.
#   PRIVILEGESECURITY=1         — Still needed for Security event log access
#                               even with a domain svc account.
#   PRIVILEGEBACKUP=1           — Still needed for file monitor inputs
#                               (dns.log path in inputs.conf).
#   PRIVILEGEIMPERSONATE=1      — Grants SeImpersonatePrivilege.
#   GROUPPERFORMANCEMONITORUSERS=1 — WMI inputs on DC.
#
# NOTE: The svc account (LOGON_USERNAME) must be pre-created in AD and
#       must have "Log on as a service" rights granted via GPO or Local
#       Security Policy before running this installer.
# ═══════════════════════════════════════════════════════════════════
} elseif ($Scenario -eq "DC") {

    $msiArgs = @(
        "/i", "`"$MsiPath`"",
        "INSTALLDIR=`"$InstallDir`"",
        "AGREETOLICENSE=Yes",
        "SPLUNKUSERNAME=$AdminUsername",
        "SPLUNKPASSWORD=$AdminPassword",
        "RECEIVING_INDEXER=`"$Receiver`"",
        "LOGON_USERNAME=`"$SvcUsername`"",
        "LOGON_PASSWORD=`"$SvcPassword`"",
        "USE_LOCAL_SYSTEM=0",
        "ENABLEADMON=1",
        "PRIVILEGESECURITY=1",
        "PRIVILEGEBACKUP=1",
        "PRIVILEGEIMPERSONATE=1",
        "GROUPPERFORMANCEMONITORUSERS=1",
        "LAUNCHSPLUNK=1",
        "SERVICESTARTTYPE=auto",
        "/quiet",
        "/l*v", "`"$env:TEMP\splunkuf-install-dc.log`""
    )

    if ($DeploymentServer) {
        $msiArgs += "DEPLOYMENT_SERVER=`"$DeploymentServer`""
    }

    Write-Host "  Running msiexec (Domain Controller)..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  msiexec.exe $($msiArgs -join ' ')" -ForegroundColor Gray
    Write-Host ""

    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    $exitCode = $proc.ExitCode
}

# ── Result ──────────────────────────────────────────────────────────
Write-Host ""
if ($exitCode -eq 0) {
    Write-Host "  Install succeeded (exit code 0)." -ForegroundColor Green
} elseif ($exitCode -eq 3010) {
    Write-Host "  Install succeeded — REBOOT REQUIRED (exit code 3010)." -ForegroundColor Yellow
} else {
    Write-Host "  Install may have failed. Exit code: $exitCode" -ForegroundColor Red
    Write-Host "  Check log: $env:TEMP\splunkuf-install-$($Scenario.ToLower()).log" -ForegroundColor Red
    exit $exitCode
}

# ── Verify service ──────────────────────────────────────────────────
Start-Sleep -Seconds 3
$svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  SplunkForwarder service: $($svc.Status)" -ForegroundColor $(
        if ($svc.Status -eq "Running") { "Green" } else { "Yellow" }
    )
} else {
    Write-Host "  SplunkForwarder service not found — check install log." -ForegroundColor Red
}

Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "  1. Copy inputs.conf  → $InstallDir\etc\system\local\" -ForegroundColor Cyan
Write-Host "  2. Copy outputs.conf → $InstallDir\etc\system\local\" -ForegroundColor Cyan
Write-Host "  3. Run prereq script → Enable-WindowsLogging-$Scenario.ps1" -ForegroundColor Cyan
Write-Host "  4. Restart service   → Restart-Service SplunkForwarder" -ForegroundColor Cyan
Write-Host ""
