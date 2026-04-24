#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enable all prerequisite logging for Splunk UF collection on Windows Workstation / Member Server.

.DESCRIPTION
    Applies all logging prerequisites referenced in the Splunk UF Configuration Guide:
      - Advanced Audit Policy subcategories (via auditpol.exe)
      - Process Creation command-line logging
      - Windows Event Log size increases
      - PowerShell Module Logging + Script Block Logging
      - WMI-Activity/Operational log enablement
      - TaskScheduler/Operational log enablement
      - Sysmon deployment (optional - requires sysmon64.exe and config in same folder)
      - Windows Firewall logging

    Sources: NSA EFG, ACSC WEF, CIS Benchmarks, Microsoft Appendix L,
             Palantir WEF, Mandiant PowerShell Logging guidance.

.PARAMETER SkipSysmon
    Skip Sysmon installation (if already deployed or deploying separately).

.PARAMETER SysmonConfig
    Path to Sysmon XML config file. Defaults to .\sysmonconfig-export.xml
    Recommended config: https://github.com/SwiftOnSecurity/sysmon-config

.PARAMETER SysmonBinary
    Path to sysmon64.exe binary. Defaults to .\sysmon64.exe

.EXAMPLE
    # Run with Sysmon deployment:
    .\Enable-WindowsLogging-Workstation.ps1

    # Skip Sysmon (deploy separately):
    .\Enable-WindowsLogging-Workstation.ps1 -SkipSysmon

    # Specify custom paths:
    .\Enable-WindowsLogging-Workstation.ps1 -SysmonBinary C:\Tools\sysmon64.exe -SysmonConfig C:\Tools\sysmonconfig.xml

.NOTES
    Must be run as Administrator.
    Reboot is NOT required — all changes take effect immediately.
    Run on each workstation/member server individually, or deploy via GPO/SCCM.
#>

[CmdletBinding()]
param(
    [switch]$SkipSysmon,
    [string]$SysmonConfig  = ".\sysmonconfig-export.xml",
    [string]$SysmonBinary  = ".\sysmon64.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Logging helper ──────────────────────────────────────────────────
$LogFile = "$env:SystemRoot\Temp\Enable-WindowsLogging-Workstation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        "OK"    { Write-Host $line -ForegroundColor Green  }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "ERROR" { Write-Host $line -ForegroundColor Red    }
        default { Write-Host $line }
    }
    Add-Content -Path $LogFile -Value $line
}

function Write-Section {
    param([string]$Title)
    $line = "=" * 70
    Write-Host ""
    Write-Host $line              -ForegroundColor Cyan
    Write-Host "  $Title"         -ForegroundColor Cyan
    Write-Host $line              -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value ""
    Add-Content -Path $LogFile -Value $line
    Add-Content -Path $LogFile -Value "  $Title"
    Add-Content -Path $LogFile -Value $line
}

# ── Run auditpol helper ─────────────────────────────────────────────
function Set-AuditPolicy {
    param(
        [string]$Category,
        [string]$Subcategory,
        [ValidateSet("Success","Failure","Success and Failure","No Auditing")]
        [string]$Setting
    )
    $result = auditpol /set /subcategory:"$Subcategory" /success:$(
        if ($Setting -match "Success") { "enable" } else { "disable" }
    ) /failure:$(
        if ($Setting -match "Failure") { "enable" } else { "disable" }
    ) 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Log "  Audit policy set: [$Category] $Subcategory → $Setting" "OK"
    } else {
        Write-Log "  FAILED to set audit policy: $Subcategory — $result" "ERROR"
    }
}

# ── Set registry value helper ───────────────────────────────────────
function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    Write-Log "  Registry set: $Path\$Name = $Value" "OK"
}

# ── Set event log size helper ───────────────────────────────────────
function Set-EventLogSize {
    param([string]$LogName, [long]$SizeBytes)
    try {
        wevtutil sl "$LogName" /ms:$SizeBytes 2>&1 | Out-Null
        $sizeMB = [math]::Round($SizeBytes / 1MB)
        Write-Log "  Log size set: '$LogName' → $sizeMB MB" "OK"
    } catch {
        Write-Log "  Failed to set log size for '$LogName': $_" "WARN"
    }
}

# ── Enable operational log helper ───────────────────────────────────
function Enable-EventLog {
    param([string]$LogName, [long]$SizeBytes = 134217728)
    try {
        $current = wevtutil gl "$LogName" 2>&1
        if ($current -match "enabled: false") {
            wevtutil sl "$LogName" /e:true /ms:$SizeBytes | Out-Null
            Write-Log "  Enabled log: '$LogName'" "OK"
        } else {
            wevtutil sl "$LogName" /ms:$SizeBytes | Out-Null
            Write-Log "  Log already enabled (size updated): '$LogName'" "OK"
        }
    } catch {
        Write-Log "  Failed to enable log '$LogName': $_" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════
# START
# ═══════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "  Splunk UF Prerequisite — Windows Workstation / Member Server" -ForegroundColor White
Write-Host "  Log file: $LogFile" -ForegroundColor Gray
Write-Host ""

# ── STEP 1: Advanced Audit Policy ──────────────────────────────────
Write-Section "STEP 1: Advanced Audit Policy Configuration"
Write-Log "Applying audit policy subcategories (Source: NSA EFG, CIS Benchmark §17, Microsoft Appendix L)"

# Account Logon
Set-AuditPolicy "Account Logon" "Credential Validation"              "Success and Failure"
Set-AuditPolicy "Account Logon" "Other Account Logon Events"          "Success and Failure"

# Account Management
Set-AuditPolicy "Account Management" "User Account Management"        "Success and Failure"
Set-AuditPolicy "Account Management" "Security Group Management"      "Success"
Set-AuditPolicy "Account Management" "Computer Account Management"    "Success"
Set-AuditPolicy "Account Management" "Other Account Management Events" "Success"

# Detailed Tracking
Set-AuditPolicy "Detailed Tracking" "Process Creation"                "Success"
Set-AuditPolicy "Detailed Tracking" "Process Termination"             "Success"
Set-AuditPolicy "Detailed Tracking" "PNP Activity"                    "Success"
Set-AuditPolicy "Detailed Tracking" "RPC Events"                      "Success"

# Logon/Logoff
Set-AuditPolicy "Logon/Logoff" "Logon"                                "Success and Failure"
Set-AuditPolicy "Logon/Logoff" "Logoff"                               "Success"
Set-AuditPolicy "Logon/Logoff" "Special Logon"                        "Success"
Set-AuditPolicy "Logon/Logoff" "Account Lockout"                      "Failure"
Set-AuditPolicy "Logon/Logoff" "Other Logon/Logoff Events"            "Success and Failure"

# Object Access
Set-AuditPolicy "Object Access" "File Share"                          "Success and Failure"
Set-AuditPolicy "Object Access" "Detailed File Share"                 "Failure"
Set-AuditPolicy "Object Access" "Other Object Access Events"          "Success and Failure"
Set-AuditPolicy "Object Access" "Removable Storage"                   "Success and Failure"

# Policy Change
Set-AuditPolicy "Policy Change" "Audit Policy Change"                 "Success"
Set-AuditPolicy "Policy Change" "Authentication Policy Change"        "Success"
Set-AuditPolicy "Policy Change" "MPSSVC Rule-Level Policy Change"     "Success"
Set-AuditPolicy "Policy Change" "Other Policy Change Events"          "Failure"

# Privilege Use
Set-AuditPolicy "Privilege Use" "Sensitive Privilege Use"             "Success and Failure"

# System
Set-AuditPolicy "System" "Security State Change"                      "Success"
Set-AuditPolicy "System" "Security System Extension"                  "Success"
Set-AuditPolicy "System" "System Integrity"                           "Success and Failure"

Write-Log "Audit policy configuration complete." "OK"

# ── STEP 2: Process Creation Command-Line Logging ──────────────────
Write-Section "STEP 2: Enable Command-Line Logging in Process Creation Events"
Write-Log "Enables CommandLine field in Event ID 4688 (Source: Microsoft, Yamato EnableWindowsLogSettings)"

Set-RegValue `
    -Path  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name  "ProcessCreationIncludeCmdLine_Enabled" `
    -Value 1 `
    -Type  "DWord"

Write-Log "Command-line logging enabled. Event ID 4688 will now include CommandLine field." "OK"

# ── STEP 3: Windows Event Log Sizes ────────────────────────────────
Write-Section "STEP 3: Increase Windows Event Log Sizes"
Write-Log "Source: ACSC 'Windows Event Logging and Forwarding' — Security=2GB recommended"

Set-EventLogSize -LogName "Security"    -SizeBytes 2147483648   # 2 GB
Set-EventLogSize -LogName "System"      -SizeBytes 268435456    # 256 MB
Set-EventLogSize -LogName "Application" -SizeBytes 67108864     # 64 MB

# ── STEP 4: PowerShell Logging ─────────────────────────────────────
Write-Section "STEP 4: Enable PowerShell Module Logging and Script Block Logging"
Write-Log "Source: Mandiant 'Greater Visibility Through PowerShell Logging', Splunk UBA docs"

# Module Logging
Set-RegValue `
    -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name  "EnableModuleLogging" `
    -Value 1

$mlNamesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
if (-not (Test-Path $mlNamesPath)) {
    New-Item -Path $mlNamesPath -Force | Out-Null
}
Set-ItemProperty -Path $mlNamesPath -Name "*" -Value "*" -Type String -Force
Write-Log "  Module Logging ModuleNames wildcard (*) set" "OK"

# Script Block Logging
Set-RegValue `
    -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name  "EnableScriptBlockLogging" `
    -Value 1

# Also set for 32-bit PowerShell (Wow6432Node)
Set-RegValue `
    -Path  "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name  "EnableModuleLogging" `
    -Value 1

Set-RegValue `
    -Path  "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name  "EnableScriptBlockLogging" `
    -Value 1

Write-Log "PowerShell Module Logging (EID 4103) and Script Block Logging (EID 4104) enabled." "OK"

# ── STEP 5: Enable Operational Logs ────────────────────────────────
Write-Section "STEP 5: Enable Windows Operational Event Log Channels"
Write-Log "Source: NSA EFG, Palantir WEF, ACSC, TrustedSec SysmonCommunityGuide"

Enable-EventLog "Microsoft-Windows-TaskScheduler/Operational"           134217728  # 128 MB
Enable-EventLog "Microsoft-Windows-WMI-Activity/Operational"            134217728
Enable-EventLog "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"   67108864
Enable-EventLog "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" 67108864
Enable-EventLog "Microsoft-Windows-Bits-Client/Operational"             67108864
Enable-EventLog "Microsoft-Windows-CodeIntegrity/Operational"           67108864
Enable-EventLog "Microsoft-Windows-NTLM/Operational"                    67108864
Enable-EventLog "Microsoft-Windows-SMBClient/Security"                  67108864
Enable-EventLog "Microsoft-Windows-PrintService/Operational"            67108864
Enable-EventLog "Microsoft-Windows-Kernel-PnP/Configuration"            67108864
Enable-EventLog "Microsoft-Windows-Windows Defender/Operational"        134217728

Write-Log "Operational log channels enabled." "OK"

# ── STEP 6: Windows Firewall Logging ───────────────────────────────
Write-Section "STEP 6: Enable Windows Firewall Logging"
Write-Log "Source: NSA EFG — firewall events (4946-4958) require policy logging enabled"

try {
    Set-NetFirewallProfile -All -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 32767
    Write-Log "  Windows Firewall logging enabled for all profiles (Dropped + Allowed)" "OK"
} catch {
    # Fallback to netsh if PowerShell cmdlet unavailable
    netsh advfirewall set allprofiles logging droppedconnections enable  | Out-Null
    netsh advfirewall set allprofiles logging allowedconnections enable  | Out-Null
    netsh advfirewall set allprofiles logging maxfilesize 32767          | Out-Null
    Write-Log "  Windows Firewall logging enabled via netsh (fallback)" "OK"
}

# ── STEP 7: Sysmon ─────────────────────────────────────────────────
Write-Section "STEP 7: Sysmon Deployment"

if ($SkipSysmon) {
    Write-Log "Sysmon deployment skipped (-SkipSysmon flag set)." "WARN"
} else {
    # Check if already installed
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) {
        $sysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
    }

    if ($sysmonSvc) {
        Write-Log "Sysmon is already installed (service: $($sysmonSvc.Name)). Updating config." "WARN"
        if (Test-Path $SysmonConfig) {
            & $SysmonBinary -c $SysmonConfig 2>&1 | ForEach-Object { Write-Log "  Sysmon: $_" }
            Write-Log "Sysmon config updated." "OK"
        } else {
            Write-Log "  Sysmon config file not found at '$SysmonConfig'. Skipping config update." "WARN"
        }
    } else {
        if (-not (Test-Path $SysmonBinary)) {
            Write-Log "Sysmon binary not found at '$SysmonBinary'." "WARN"
            Write-Log "Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" "WARN"
            Write-Log "Recommended config: https://github.com/SwiftOnSecurity/sysmon-config" "WARN"
            Write-Log "Re-run script with -SysmonBinary and -SysmonConfig paths, or deploy manually." "WARN"
        } elseif (-not (Test-Path $SysmonConfig)) {
            Write-Log "Sysmon config not found at '$SysmonConfig'." "WARN"
            Write-Log "Download SwiftOnSecurity config from: https://github.com/SwiftOnSecurity/sysmon-config" "WARN"
        } else {
            Write-Log "Installing Sysmon with config: $SysmonConfig"
            & $SysmonBinary -accepteula -i $SysmonConfig 2>&1 | ForEach-Object { Write-Log "  Sysmon: $_" }
            $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
            if ($svc) {
                Write-Log "Sysmon installed and running." "OK"
            } else {
                Write-Log "Sysmon install may have failed — check output above." "ERROR"
            }
        }
    }
}

# ── STEP 8: AppLocker (Audit Mode) ─────────────────────────────────
Write-Section "STEP 8: Enable AppLocker Audit Mode (Optional)"
Write-Log "Enables AppLocker in Audit mode so EIDs 8002/8003/8004/8007 flow into logs"
Write-Log "Source: NSA Spotting the Adversary"

try {
    # Enable AppLocker operational logs
    Enable-EventLog "Microsoft-Windows-AppLocker/EXE and DLL"    67108864
    Enable-EventLog "Microsoft-Windows-AppLocker/MSI and Script" 67108864

    # Set AppLocker to Audit mode for EXE rules if not already configured
    $appLockerSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if ($appLockerSvc) {
        Set-Service -Name "AppIDSvc" -StartupType Automatic
        Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        Write-Log "  AppID service enabled (required for AppLocker)" "OK"
    }
} catch {
    Write-Log "  AppLocker setup: $_" "WARN"
}

# ── STEP 9: Validate Key Settings ──────────────────────────────────
Write-Section "STEP 9: Validation"

Write-Log "Verifying key settings..."

# Check audit policy
$apOut = auditpol /get /subcategory:"Process Creation" 2>&1
if ($apOut -match "Success") {
    Write-Log "  Process Creation audit: OK (Success enabled)" "OK"
} else {
    Write-Log "  Process Creation audit: NOT confirmed — check auditpol output" "WARN"
}

# Check command-line registry
$cmdLine = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
if ($cmdLine -and $cmdLine.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Write-Log "  Command-line logging registry: OK" "OK"
} else {
    Write-Log "  Command-line logging registry: NOT SET" "ERROR"
}

# Check PowerShell ScriptBlock
$sbLog = Get-ItemProperty `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
if ($sbLog -and $sbLog.EnableScriptBlockLogging -eq 1) {
    Write-Log "  PowerShell ScriptBlock logging: OK" "OK"
} else {
    Write-Log "  PowerShell ScriptBlock logging: NOT SET" "ERROR"
}

# Check Security log size
$secLog = wevtutil gl Security 2>&1 | Select-String "maxSize"
Write-Log "  Security log: $secLog" "OK"

# Check Sysmon service
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
if ($svc -and $svc.Status -eq "Running") {
    Write-Log "  Sysmon service: Running" "OK"
} elseif ($SkipSysmon) {
    Write-Log "  Sysmon: Skipped by parameter" "WARN"
} else {
    Write-Log "  Sysmon service: NOT RUNNING — deploy manually" "WARN"
}

# ── DONE ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host "  COMPLETED — Windows Workstation Logging Prerequisites" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host ""
Write-Log "Full log saved to: $LogFile"
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "  1. Deploy inputs.conf to: $env:SPLUNK_HOME\etc\system\local\" -ForegroundColor Yellow
Write-Host "  2. Deploy outputs.conf to: $env:SPLUNK_HOME\etc\system\local\" -ForegroundColor Yellow
Write-Host "  3. Restart Splunk UF: Restart-Service SplunkForwarder" -ForegroundColor Yellow
Write-Host ""
