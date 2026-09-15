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
    [string]$SysmonConfig = ".\sysmonconfig-export.xml",
    [string]$SysmonBinary = ".\sysmon64.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Logging helper ──────────────────────────────────────────────────
$LogFile = "$env:SystemRoot\Temp\Enable-WindowsLogging-Workstation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"

    switch ($Level) {
        "OK" {
            Write-Host $line -ForegroundColor Green
        }
        "WARN" {
            Write-Host $line -ForegroundColor Yellow
        }
        "ERROR" {
            Write-Host $line -ForegroundColor Red
        }
        default {
            Write-Host $line
        }
    }

    Add-Content -Path $LogFile -Value $line
}

function Write-Section {
    param(
        [string]$Title
    )

    $line = "=" * 70

    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan

    Add-Content -Path $LogFile -Value ""
    Add-Content -Path $LogFile -Value $line
    Add-Content -Path $LogFile -Value "  $Title"
    Add-Content -Path $LogFile -Value $line
}

# ── Native command helper ───────────────────────────────────────────
function Invoke-Native {
    <#
        Runs a native executable and returns its exit code plus output.

        Windows PowerShell 5.1 wraps every stderr line from a native command
        in a NativeCommandError ErrorRecord. Under $ErrorActionPreference =
        "Stop" that becomes a TERMINATING error, so a tool that merely prints
        a banner to stderr (Sysmon, many Sysinternals tools) aborts the whole
        script even when it exited 0. Isolate the call and judge success by
        the exit code instead.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    try {
        # Stderr lines arrive as ErrorRecords - take the message, or they render
        # as "System.Management.Automation.RemoteException". Strip NUL bytes too:
        # Sysinternals tools (Sysmon) write UTF-16, which PS 5.1 decodes as ANSI,
        # so every character arrives NUL-separated.
        $out = & $FilePath @Arguments 2>&1 |
                   ForEach-Object {
                       $text = if ($_ -is [System.Management.Automation.ErrorRecord]) {
                           $_.Exception.Message
                       } else {
                           "$_"
                       }

                       $text.Replace([string][char]0, '').Trim()
                   } |
                   Where-Object { $_ }

        [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = @($out)
        }
    }
    finally {
        $ErrorActionPreference = $prevEAP
    }
}

# ── Step wrapper ────────────────────────────────────────────────────
$script:FailedSteps = @()

function Invoke-Step {
    <#
        Runs one step in isolation. A failure is logged and recorded, then
        the script continues with the remaining steps. A hardening script
        deployed by GPO must never leave an endpoint half-configured just
        because one step failed on one OS build.
    #>
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][scriptblock]$Body
    )

    Write-Section $Title

    try {
        & $Body
    }
    catch {
        $script:FailedSteps += $Title

        Write-Log "STEP FAILED: $Title" "ERROR"
        Write-Log "  $($_.Exception.Message)" "ERROR"
        Write-Log "  Continuing with remaining steps." "WARN"
    }
}

# ── Run auditpol helper ─────────────────────────────────────────────
function Set-AuditPolicy {
    param(
        [string]$Category,
        [string]$Subcategory,
        [ValidateSet(
            "Success",
            "Failure",
            "Success and Failure",
            "No Auditing"
        )]
        [string]$Setting
    )

    $success = if ($Setting -match "Success") { "enable" } else { "disable" }
    $failure = if ($Setting -match "Failure") { "enable" } else { "disable" }

    $r = Invoke-Native "auditpol.exe" @(
        "/set"
        "/subcategory:$Subcategory"
        "/success:$success"
        "/failure:$failure"
    )

    if ($r.ExitCode -eq 0) {
        Write-Log "  Audit policy set: [$Category] $Subcategory -> $Setting" "OK"
    }
    else {
        Write-Log "  FAILED to set audit policy: $Subcategory (exit $($r.ExitCode)) $($r.Output -join ' ')" "ERROR"
    }
}

# ── Set registry value helper ───────────────────────────────────────
function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    Set-ItemProperty `
        -Path $Path `
        -Name $Name `
        -Value $Value `
        -Type $Type `
        -Force

    Write-Log "  Registry set: $Path\$Name = $Value" "OK"
}

# ── Set event log size helper ───────────────────────────────────────
function Set-EventLogSize {
    param(
        [string]$LogName,
        [long]$SizeBytes
    )

    $r = Invoke-Native "wevtutil.exe" @("sl", $LogName, "/ms:$SizeBytes")

    if ($r.ExitCode -ne 0) {
        Write-Log "  Failed to set log size for '$LogName' (exit $($r.ExitCode)): $($r.Output -join ' ')" "WARN"
        return
    }

    $sizeMB = [math]::Round($SizeBytes / 1MB)

    # wevtutil exits 0 even when a policy value silently overrides what it just
    # wrote, so confirm the channel actually reports the requested size. Without
    # this check the script reports 2 GB while the log is really capped far lower.
    $effective = $null

    try {
        $effective = (Get-WinEvent -ListLog $LogName -ErrorAction Stop).MaximumSizeInBytes
    }
    catch {
        # Channel not queryable - fall through and trust the exit code.
    }

    if ($null -ne $effective -and $effective -ne $SizeBytes) {

        $effMB = [math]::Round($effective / 1MB)

        Write-Log "  Log size for '$LogName' NOT APPLIED - requested $sizeMB MB, effective $effMB MB" "WARN"
        Write-Log "    A policy value is overriding it. Check (size is in KB here):" "WARN"
        Write-Log "    HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$LogName\MaxSize" "WARN"
        Write-Log "    On domain members set it via GPO: Computer Configuration > Policies >" "WARN"
        Write-Log "    Administrative Templates > Windows Components > Event Log Service > $LogName" "WARN"
    }
    else {
        Write-Log "  Log size set: '$LogName' -> $sizeMB MB" "OK"
    }
}

# ── Enable operational log helper ───────────────────────────────────
function Enable-EventLog {
    param(
        [string]$LogName,
        [long]$SizeBytes = 134217728
    )

    $probe = Invoke-Native "wevtutil.exe" @("gl", $LogName)

    if ($probe.ExitCode -ne 0) {
        Write-Log "  Channel not available on this host: '$LogName' - skipping" "WARN"
        return
    }

    if ($probe.Output -match "enabled: false") {
        $r = Invoke-Native "wevtutil.exe" @("sl", $LogName, "/e:true", "/ms:$SizeBytes")
        $action = "Enabled log"
    }
    else {
        $r = Invoke-Native "wevtutil.exe" @("sl", $LogName, "/ms:$SizeBytes")
        $action = "Log already enabled (size updated)"
    }

    if ($r.ExitCode -eq 0) {
        Write-Log "  ${action}: '$LogName'" "OK"
    }
    else {
        Write-Log "  Failed to configure log '$LogName' (exit $($r.ExitCode)): $($r.Output -join ' ')" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════
# START
# ═══════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  Splunk UF Prerequisite - Windows Workstation / Member Server" -ForegroundColor White
Write-Host "  Log file: $LogFile" -ForegroundColor Gray
Write-Host ""

# ── STEP 1: Advanced Audit Policy ──────────────────────────────────
Invoke-Step "STEP 1: Advanced Audit Policy Configuration" {
Write-Log "Applying audit policy subcategories (Source: NSA EFG, CIS Benchmark, Microsoft Appendix L)"

# Account Logon
Set-AuditPolicy "Account Logon" "Credential Validation" "Success and Failure"
Set-AuditPolicy "Account Logon" "Other Account Logon Events" "Success and Failure"

# Account Management
Set-AuditPolicy "Account Management" "User Account Management" "Success and Failure"
Set-AuditPolicy "Account Management" "Security Group Management" "Success"
Set-AuditPolicy "Account Management" "Computer Account Management" "Success"
Set-AuditPolicy "Account Management" "Other Account Management Events" "Success"

# Detailed Tracking
Set-AuditPolicy "Detailed Tracking" "Process Creation" "Success"
# Process Termination (4689) fires 1:1 with 4688 for ~80 MB/day of Security
# log and is not forwarded; Sysmon EID 5 (ProcessTerminate) covers it. Set
# explicitly to "No Auditing" rather than just omitting the line - omitting
# leaves it enabled on hosts where an earlier run or a baseline turned it on.
Set-AuditPolicy "Detailed Tracking" "Process Termination" "No Auditing"
Set-AuditPolicy "Detailed Tracking" "Plug and Play Events" "Success"
Set-AuditPolicy "Detailed Tracking" "RPC Events" "Success"

# Logon/Logoff
Set-AuditPolicy "Logon/Logoff" "Logon" "Success and Failure"
Set-AuditPolicy "Logon/Logoff" "Logoff" "Success"
Set-AuditPolicy "Logon/Logoff" "Special Logon" "Success"
Set-AuditPolicy "Logon/Logoff" "Account Lockout" "Failure"
Set-AuditPolicy "Logon/Logoff" "Other Logon/Logoff Events" "Success and Failure"

# Object Access
Set-AuditPolicy "Object Access" "File Share" "Success and Failure"
Set-AuditPolicy "Object Access" "Detailed File Share" "Failure"
Set-AuditPolicy "Object Access" "Other Object Access Events" "Success and Failure"
Set-AuditPolicy "Object Access" "Removable Storage" "Success and Failure"

# Policy Change
Set-AuditPolicy "Policy Change" "Audit Policy Change" "Success"
Set-AuditPolicy "Policy Change" "Authentication Policy Change" "Success"
Set-AuditPolicy "Policy Change" "MPSSVC Rule-Level Policy Change" "Success"
Set-AuditPolicy "Policy Change" "Other Policy Change Events" "Failure"

# Privilege Use
# Failure-only: successful 4674 is ~58 MB/day of noise and is not forwarded.
# Sysmon EID 10 (ProcessAccess) is the stronger credential-dumping signal.
Set-AuditPolicy "Privilege Use" "Sensitive Privilege Use" "Failure"

# System
Set-AuditPolicy "System" "Security State Change" "Success"
Set-AuditPolicy "System" "Security System Extension" "Success"
# Failure-only: successful 5061 (crypto operation) is ~74 MB/day and is not
# forwarded. Failures retain the high-value signals: 5038 (image hash invalid),
# 5056/5057 (crypto self-test failure), 4612 (audit queue exhausted).
Set-AuditPolicy "System" "System Integrity" "Failure"

Write-Log "Audit policy configuration complete." "OK"
}

# ── STEP 2: Process Creation Command-Line Logging ──────────────────
Invoke-Step "STEP 2: Enable Command-Line Logging in Process Creation Events" {
Write-Log "Enables CommandLine field in Event ID 4688 (Source: Microsoft, Yamato EnableWindowsLogSettings)"

Set-RegValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" `
    -Value 1 `
    -Type "DWord"

Write-Log "Command-line logging enabled. Event ID 4688 will now include CommandLine field." "OK"
}

# ── STEP 3: Windows Event Log Sizes ────────────────────────────────
Invoke-Step "STEP 3: Increase Windows Event Log Sizes" {
Write-Log "Source: ACSC 'Windows Event Logging and Forwarding' - Security=2GB recommended"

Set-EventLogSize -LogName "Security" -SizeBytes 2147483648
Set-EventLogSize -LogName "System" -SizeBytes 268435456
Set-EventLogSize -LogName "Application" -SizeBytes 67108864
}

# ── STEP 4: PowerShell Logging ─────────────────────────────────────
Invoke-Step "STEP 4: Enable PowerShell Module Logging and Script Block Logging" {
Write-Log "Source: Mandiant 'Greater Visibility Through PowerShell Logging', Splunk UBA docs"

# Module Logging
Set-RegValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" `
    -Value 1

$mlNamesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"

if (-not (Test-Path $mlNamesPath)) {
    New-Item -Path $mlNamesPath -Force | Out-Null
}

Set-ItemProperty `
    -Path $mlNamesPath `
    -Name "*" `
    -Value "*" `
    -Type String `
    -Force

Write-Log "  Module Logging ModuleNames wildcard (*) set" "OK"

# Script Block Logging
Set-RegValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" `
    -Value 1

# Also set for 32-bit PowerShell (Wow6432Node)
Set-RegValue `
    -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" `
    -Value 1

Set-RegValue `
    -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" `
    -Value 1

Write-Log "PowerShell Module Logging (EID 4103) and Script Block Logging (EID 4104) enabled." "OK"
}

# ── STEP 5: Enable Operational Logs ────────────────────────────────
Invoke-Step "STEP 5: Enable Windows Operational Event Log Channels" {
Write-Log "Source: NSA EFG, Palantir WEF, ACSC, TrustedSec SysmonCommunityGuide"

Enable-EventLog "Microsoft-Windows-TaskScheduler/Operational" 134217728
Enable-EventLog "Microsoft-Windows-WMI-Activity/Operational" 134217728
Enable-EventLog "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" 67108864
Enable-EventLog "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" 67108864
Enable-EventLog "Microsoft-Windows-Bits-Client/Operational" 67108864
Enable-EventLog "Microsoft-Windows-CodeIntegrity/Operational" 67108864
Enable-EventLog "Microsoft-Windows-NTLM/Operational" 67108864
Enable-EventLog "Microsoft-Windows-SMBClient/Security" 67108864
Enable-EventLog "Microsoft-Windows-PrintService/Operational" 67108864
Enable-EventLog "Microsoft-Windows-Kernel-PnP/Configuration" 67108864
Enable-EventLog "Microsoft-Windows-Windows Defender/Operational" 134217728

Write-Log "Operational log channels enabled." "OK"
}

# ── STEP 6: Windows Firewall Logging ───────────────────────────────
Invoke-Step "STEP 6: Enable Windows Firewall Logging" {
Write-Log "Source: NSA EFG - firewall events (4946-4958) require policy logging enabled"

try {
    Set-NetFirewallProfile `
        -All `
        -LogBlocked True `
        -LogAllowed True `
        -LogMaxSizeKilobytes 32767

    Write-Log "  Windows Firewall logging enabled for all profiles (Dropped + Allowed)" "OK"
}
catch {
    # Fallback to netsh if PowerShell cmdlet unavailable
    Write-Log "  Set-NetFirewallProfile unavailable, falling back to netsh: $($_.Exception.Message)" "WARN"

    $fw = @(
        Invoke-Native "netsh.exe" @("advfirewall","set","allprofiles","logging","droppedconnections","enable")
        Invoke-Native "netsh.exe" @("advfirewall","set","allprofiles","logging","allowedconnections","enable")
        Invoke-Native "netsh.exe" @("advfirewall","set","allprofiles","logging","maxfilesize","32767")
    )

    $failed = @($fw | Where-Object { $_.ExitCode -ne 0 })

    if ($failed.Count -eq 0) {
        Write-Log "  Windows Firewall logging enabled via netsh (fallback)" "OK"
    }
    else {
        Write-Log "  Windows Firewall logging fallback failed on $($failed.Count) of 3 netsh calls" "WARN"
    }
}
}

# ── STEP 7: Sysmon ─────────────────────────────────────────────────
Invoke-Step "STEP 7: Sysmon Deployment" {
if ($SkipSysmon) {

    Write-Log "Sysmon deployment skipped (-SkipSysmon flag set)." "WARN"

}
else {

    # Check if already installed
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

    if (-not $sysmonSvc) {
        $sysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
    }

    if ($sysmonSvc) {

        Write-Log "Sysmon is already installed (service: $($sysmonSvc.Name)). Updating config." "WARN"

        if (Test-Path $SysmonConfig) {

            $r = Invoke-Native $SysmonBinary @("-c", $SysmonConfig)

            $r.Output | ForEach-Object { Write-Log "  Sysmon: $_" }

            if ($r.ExitCode -eq 0) {
                Write-Log "Sysmon config updated." "OK"
            }
            else {
                Write-Log "Sysmon config update FAILED (exit $($r.ExitCode))." "ERROR"
            }

        }
        else {

            Write-Log "  Sysmon config file not found at '$SysmonConfig'. Skipping config update." "WARN"

        }

    }
    else {

        if (-not (Test-Path $SysmonBinary)) {

            Write-Log "Sysmon binary not found at '$SysmonBinary'." "WARN"
            Write-Log "Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" "WARN"
            Write-Log "Recommended config: https://github.com/SwiftOnSecurity/sysmon-config" "WARN"
            Write-Log "Re-run script with -SysmonBinary and -SysmonConfig paths, or deploy manually." "WARN"

        }
        elseif (-not (Test-Path $SysmonConfig)) {

            Write-Log "Sysmon config not found at '$SysmonConfig'." "WARN"
            Write-Log "Download SwiftOnSecurity config from: https://github.com/SwiftOnSecurity/sysmon-config" "WARN"

        }
        else {

            Write-Log "Installing Sysmon with config: $SysmonConfig"

            $r = Invoke-Native $SysmonBinary @("-accepteula", "-i", $SysmonConfig)

            $r.Output | ForEach-Object { Write-Log "  Sysmon: $_" }

            $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

            if ($svc) {
                Write-Log "Sysmon installed and running." "OK"
            }
            else {
                Write-Log "Sysmon install FAILED (exit $($r.ExitCode)) - check output above." "ERROR"
            }
        }
    }
}
}

# ── STEP 8: AppLocker (Audit Mode) ─────────────────────────────────
Invoke-Step "STEP 8: Enable AppLocker Audit Mode (Optional)" {
Write-Log "Enables AppLocker in Audit mode so EIDs 8002/8003/8004/8007 flow into logs"
Write-Log "Source: NSA Spotting the Adversary"

try {

    # Enable AppLocker operational logs
    Enable-EventLog "Microsoft-Windows-AppLocker/EXE and DLL" 67108864
    Enable-EventLog "Microsoft-Windows-AppLocker/MSI and Script" 67108864

    # Enable AppID service
    $appLockerSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue

    if ($appLockerSvc) {

        Set-Service -Name "AppIDSvc" -StartupType Automatic

        Start-Service `
            -Name "AppIDSvc" `
            -ErrorAction SilentlyContinue

        Write-Log "  AppID service enabled (required for AppLocker)" "OK"
    }
}
catch {
    Write-Log "  AppLocker setup: $_" "WARN"
}
}

# ── STEP 9: Validate Key Settings ──────────────────────────────────
Invoke-Step "STEP 9: Validation" {
Write-Log "Verifying key settings..."

# Check audit policy
$apOut = (Invoke-Native "auditpol.exe" @("/get", "/subcategory:Process Creation")).Output

if ($apOut -match "Success") {
    Write-Log "  Process Creation audit: OK (Success enabled)" "OK"
}
else {
    Write-Log "  Process Creation audit: NOT confirmed - check auditpol output" "WARN"
}

# Check command-line registry
$cmdLine = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" `
    -ErrorAction SilentlyContinue

if ($cmdLine -and $cmdLine.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Write-Log "  Command-line logging registry: OK" "OK"
}
else {
    Write-Log "  Command-line logging registry: NOT SET" "ERROR"
}

# Check PowerShell ScriptBlock
$sbLog = Get-ItemProperty `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" `
    -ErrorAction SilentlyContinue

if ($sbLog -and $sbLog.EnableScriptBlockLogging -eq 1) {
    Write-Log "  PowerShell ScriptBlock logging: OK" "OK"
}
else {
    Write-Log "  PowerShell ScriptBlock logging: NOT SET" "ERROR"
}

# Check Security log size
$secLog = (Invoke-Native "wevtutil.exe" @("gl", "Security")).Output |
              Where-Object { $_ -match "maxSize" }

Write-Log "  Security log: $($secLog -join ' ')" "OK"

# Check Sysmon service
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

if (-not $svc) {
    $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if ($svc -and $svc.Status -eq "Running") {

    Write-Log "  Sysmon service: Running" "OK"

}
elseif ($SkipSysmon) {

    Write-Log "  Sysmon: Skipped by parameter" "WARN"

}
else {

    Write-Log "  Sysmon service: NOT RUNNING - deploy manually" "WARN"

}
}

# ── DONE ───────────────────────────────────────────────────────────
$hasFailures = $script:FailedSteps.Count -gt 0
$banner      = if ($hasFailures) { "Red" } else { "Green" }
$headline    = if ($hasFailures) {
    "  COMPLETED WITH ERRORS - Windows Workstation Logging Prerequisites"
} else {
    "  COMPLETED - Windows Workstation Logging Prerequisites"
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor $banner
Write-Host $headline -ForegroundColor $banner
Write-Host ("=" * 70) -ForegroundColor $banner
Write-Host ""

if ($hasFailures) {
    Write-Log "$($script:FailedSteps.Count) step(s) failed:" "ERROR"

    foreach ($f in $script:FailedSteps) {
        Write-Log "  - $f" "ERROR"
    }
}
else {
    Write-Log "All steps completed successfully." "OK"
}

Write-Log "Full log saved to: $LogFile"

Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
$splunkHome = if ($env:SPLUNK_HOME) {
    $env:SPLUNK_HOME
} else {
    "C:\Program Files\SplunkUniversalForwarder"
}

Write-Host "  1. Deploy inputs.conf to: $splunkHome\etc\system\local\" -ForegroundColor Yellow
Write-Host "  2. Deploy outputs.conf to: $splunkHome\etc\system\local\" -ForegroundColor Yellow
Write-Host "  3. Restart Splunk UF: Restart-Service SplunkForwarder" -ForegroundColor Yellow
Write-Host ""

# Exit non-zero when any step failed, so GPO / SCCM / Intune can detect it.
if ($script:FailedSteps.Count -gt 0) {
    exit 1
}

exit 0
