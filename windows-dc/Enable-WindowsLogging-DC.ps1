#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enable all prerequisite logging for Splunk UF collection on a Windows Domain Controller.

.DESCRIPTION
    Applies ALL workstation logging prerequisites PLUS DC-specific additions:
      - Kerberos authentication + service-ticket audit policy (4768, 4769, 4771)
      - DS Access: Directory Service Changes (5136-5139, 5141)
      - DS Access: Directory Service Access (4662 - DCSync detection)
      - DS Access: Directory Service Replication (4932, 4933)
      - Privilege Use: Sensitive Privilege Use (4673, 4674)
      - DNS Server debug logging (dns.log)
      - ADFS operational log enablement (if ADFS role present)
      - DFS Replication and File Replication Service logs
      - Directory Service log size increase

    Sources: NSA EFG, ACSC WEF, Microsoft Appendix L, JSCU-NL logging-essentials,
             Palantir WEF, CIS Benchmarks sec 17.

.PARAMETER SkipSysmon
    Skip Sysmon installation.

.PARAMETER SysmonConfig
    Path to Sysmon XML config. Defaults to .\sysmonconfig-export.xml

.PARAMETER SysmonBinary
    Path to sysmon64.exe. Defaults to .\sysmon64.exe

.PARAMETER SkipDNSLogging
    Skip DNS Server debug logging enablement.

.EXAMPLE
    .\Enable-WindowsLogging-DC.ps1
    .\Enable-WindowsLogging-DC.ps1 -SkipSysmon -SkipDNSLogging

.NOTES
    Must be run as Domain Admin (or equivalent) on the DC itself.
    Run on EACH domain controller in the environment.
#>

[CmdletBinding()]
param(
    [switch]$SkipSysmon,
    [switch]$SkipDNSLogging,
    [switch]$Force,
    [string]$SysmonConfig = ".\sysmonconfig-export.xml",
    [string]$SysmonBinary = ".\sysmon64.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$LogFile = "$env:SystemRoot\Temp\Enable-WindowsLogging-DC_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
    Write-Host ""; Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value "`n$line`n  $Title`n$line"
}

function Invoke-Native {
    <#
        Runs a native executable and returns its exit code plus output.

        Windows PowerShell 5.1 wraps every stderr line from a native command in
        a NativeCommandError ErrorRecord. Under $ErrorActionPreference = "Stop"
        that becomes a TERMINATING error, so a tool that merely prints a banner
        to stderr (Sysmon and most Sysinternals tools) aborts the whole script
        even when it exited 0. Isolate the call, judge success by the exit code.
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
        # Sysinternals tools write UTF-16, which PS 5.1 decodes as ANSI, so every
        # character arrives NUL-separated.
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

        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = @($out) }
    }
    finally {
        $ErrorActionPreference = $prevEAP
    }
}

$script:FailedSteps = @()

function Invoke-Step {
    <#
        Runs one step in isolation. A failure is logged and recorded, then the
        script continues. A DC hardening script must never leave a controller
        half-configured because one step failed on one OS build.
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

function Set-AuditPolicy {
    param([string]$Category, [string]$Subcategory, [string]$Setting)
    $success = if ($Setting -match "Success") { "enable" } else { "disable" }
    $failure = if ($Setting -match "Failure") { "enable" } else { "disable" }
    $r = Invoke-Native "auditpol.exe" @(
        "/set"
        "/subcategory:$Subcategory"
        "/success:$success"
        "/failure:$failure"
    )

    if ($r.ExitCode -eq 0) {
        Write-Log "  Audit: [$Category] $Subcategory -> $Setting" "OK"
    } else {
        Write-Log "  FAILED: $Subcategory (exit $($r.ExitCode)) $($r.Output -join ' ')" "ERROR"
    }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    Write-Log "  Registry: $Path\$Name = $Value" "OK"
}

function Set-EventLogSize {
    param([string]$LogName, [long]$SizeBytes)
    $r = Invoke-Native "wevtutil.exe" @("sl", $LogName, "/ms:$SizeBytes")

    if ($r.ExitCode -ne 0) {
        Write-Log "  Failed to set size for '$LogName' (exit $($r.ExitCode)): $($r.Output -join ' ')" "WARN"
        return
    }

    $sizeMB = [math]::Round($SizeBytes / 1MB)

    # wevtutil exits 0 even when a policy value silently overrides what it just
    # wrote, so confirm the channel actually reports the requested size.
    $effective = $null
    try { $effective = (Get-WinEvent -ListLog $LogName -ErrorAction Stop).MaximumSizeInBytes } catch { }

    if ($null -ne $effective -and $effective -ne $SizeBytes) {
        Write-Log "  Log size for '$LogName' NOT APPLIED - requested $sizeMB MB, effective $([math]::Round($effective/1MB)) MB" "WARN"
        Write-Log "    Overridden by policy. On a DC this is almost always the Default Domain" "WARN"
        Write-Log "    Controllers Policy GPO: Computer Configuration > Policies > Administrative" "WARN"
        Write-Log "    Templates > Windows Components > Event Log Service > $LogName (size in KB)" "WARN"
    } else {
        Write-Log "  Log size: '$LogName' -> $sizeMB MB" "OK"
    }
}

function Enable-EventLog {
    param([string]$LogName, [long]$SizeBytes = 134217728)
    $probe = Invoke-Native "wevtutil.exe" @("gl", $LogName)

    if ($probe.ExitCode -ne 0) {
        Write-Log "  Channel not available on this host: '$LogName' - skipping" "WARN"
        return
    }

    if ($probe.Output -match "enabled: false") {
        $r = Invoke-Native "wevtutil.exe" @("sl", $LogName, "/e:true", "/ms:$SizeBytes")
        $action = "Enabled log"
    } else {
        $r = Invoke-Native "wevtutil.exe" @("sl", $LogName, "/ms:$SizeBytes")
        $action = "Log already enabled (size updated)"
    }

    if ($r.ExitCode -eq 0) {
        Write-Log "  ${action}: '$LogName'" "OK"
    } else {
        Write-Log "  Failed to configure '$LogName' (exit $($r.ExitCode)): $($r.Output -join ' ')" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════
# START
# ═══════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "  Splunk UF Prerequisite - Windows Domain Controller" -ForegroundColor White
Write-Host "  Log file: $LogFile" -ForegroundColor Gray
Write-Host ""

# Confirm this is a DC
$dcRole = (Get-CimInstance Win32_ComputerSystem).DomainRole

if ($dcRole -lt 4) {
    Write-Log "WARNING: This machine does not appear to be a Domain Controller (DomainRole=$dcRole)." "WARN"
    Write-Log "DC-specific audit policies (Kerberos, DS Access) will apply but produce no events." "WARN"

    # Never block on input: this script is deployed unattended (GPO / scheduled
    # task / remoting), where Read-Host reads EOF and no one sees the prompt.
    if ($Force) {
        Write-Log "-Force specified - continuing on a non-DC host." "WARN"
    } else {
        Write-Log "Refusing to run on a non-DC. Re-run with -Force to override." "ERROR"
        exit 2
    }
}

# ── STEP 1: All Workstation Audit Policies ─────────────────────────
Invoke-Step "STEP 1: Base Audit Policies (Workstation + DC)" {
Write-Log "Source: NSA EFG, CIS Benchmark sec 17, Microsoft Appendix L"

# Account Logon
Set-AuditPolicy "Account Logon" "Credential Validation"               "Success and Failure"
Set-AuditPolicy "Account Logon" "Kerberos Authentication Service"     "Success and Failure"  # DC-specific: 4768, 4771
Set-AuditPolicy "Account Logon" "Kerberos Service Ticket Operations"  "Success and Failure"  # DC-specific: 4769, 4770
Set-AuditPolicy "Account Logon" "Other Account Logon Events"          "Success and Failure"

# Account Management
Set-AuditPolicy "Account Management" "User Account Management"        "Success and Failure"
Set-AuditPolicy "Account Management" "Security Group Management"      "Success"
Set-AuditPolicy "Account Management" "Computer Account Management"    "Success"              # DC: 4741-4743
Set-AuditPolicy "Account Management" "Distribution Group Management"  "Success"
Set-AuditPolicy "Account Management" "Other Account Management Events" "Success"

# Detailed Tracking
Set-AuditPolicy "Detailed Tracking" "Process Creation"                "Success"
# 4689 fires 1:1 with 4688 and is not forwarded; Sysmon EID 5 covers process
# termination. Set explicitly rather than omitted - omitting leaves it enabled
# on controllers where an earlier run or a baseline turned it on.
Set-AuditPolicy "Detailed Tracking" "Process Termination"             "No Auditing"
Set-AuditPolicy "Detailed Tracking" "Plug and Play Events"                    "Success"
Set-AuditPolicy "Detailed Tracking" "RPC Events"                      "Success"

# DS Access - DC-SPECIFIC
Write-Log "Applying DC-specific DS Access audit policies..."
Set-AuditPolicy "DS Access" "Directory Service Changes"               "Success"              # 5136-5141
Set-AuditPolicy "DS Access" "Directory Service Access"                "Success and Failure"  # 4662 (DCSync)
Set-AuditPolicy "DS Access" "Directory Service Replication"           "Success and Failure"  # 4932, 4933
Set-AuditPolicy "DS Access" "Detailed Directory Service Replication"  "Failure"

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
Set-AuditPolicy "Object Access" "Certification Services"              "Success and Failure"  # ADCS on DC
Set-AuditPolicy "Object Access" "Removable Storage"              "Success and Failure"  # USB on a DC is always notable

# Policy Change
Set-AuditPolicy "Policy Change" "Audit Policy Change"                 "Success"
Set-AuditPolicy "Policy Change" "Authentication Policy Change"        "Success"
Set-AuditPolicy "Policy Change" "MPSSVC Rule-Level Policy Change"     "Success"
Set-AuditPolicy "Policy Change" "Other Policy Change Events"          "Failure"

# Privilege Use - DC-SPECIFIC (SeDebug on DC = high criticality)
Set-AuditPolicy "Privilege Use" "Sensitive Privilege Use"             "Success and Failure"
Set-AuditPolicy "Privilege Use" "Non Sensitive Privilege Use"         "Failure"

# System
Set-AuditPolicy "System" "Security State Change"                      "Success"
Set-AuditPolicy "System" "Security System Extension"                  "Success"
# Failure-only: successful 5061 (cryptographic operation) is high volume on a
# DC because Kerberos emits one per operation, and it is not forwarded.
# Failures retain 5038 (image hash invalid) and 5056/5057 (crypto self-test).
Set-AuditPolicy "System" "System Integrity"                           "Failure"

Write-Log "Audit policy configuration complete." "OK"
}

# ── STEP 2: Process Creation Command-Line ──────────────────────────
Invoke-Step "STEP 2: Enable Command-Line Logging in Process Creation Events" {
Set-RegValue `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    "ProcessCreationIncludeCmdLine_Enabled" 1
}

# ── STEP 3: Event Log Sizes ─────────────────────────────────────────
Invoke-Step "STEP 3: Increase Event Log Sizes" {
Write-Log "DC logs receive higher volume - Directory Service log set to 512 MB"

Set-EventLogSize "Security"           2147483648   # 2 GB
Set-EventLogSize "System"             268435456    # 256 MB
Set-EventLogSize "Application"        67108864     # 64 MB
Set-EventLogSize "Directory Service"  536870912    # 512 MB  (DC-specific)
}

# ── STEP 4: PowerShell Logging ─────────────────────────────────────
Invoke-Step "STEP 4: PowerShell Module + Script Block Logging" {
Write-Log "Source: Mandiant PowerShell Logging guidance, Splunk UBA prerequisites"

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    "EnableModuleLogging" 1

$mlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
if (-not (Test-Path $mlPath)) { New-Item -Path $mlPath -Force | Out-Null }
Set-ItemProperty -Path $mlPath -Name "*" -Value "*" -Type String -Force
Write-Log "  Module Logging wildcard (*) set" "OK"

Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    "EnableScriptBlockLogging" 1

Set-RegValue "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    "EnableModuleLogging" 1
Set-RegValue "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    "EnableScriptBlockLogging" 1

Write-Log "PowerShell logging enabled (EID 4103 + 4104)." "OK"
}

# ── STEP 5: Operational Logs ────────────────────────────────────────
Invoke-Step "STEP 5: Enable Operational Log Channels" {
Write-Log "Source: NSA EFG, Palantir WEF, ACSC, TrustedSec SysmonCommunityGuide"

Enable-EventLog "Microsoft-Windows-TaskScheduler/Operational"                         134217728
Enable-EventLog "Microsoft-Windows-WMI-Activity/Operational"                          134217728
Enable-EventLog "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"  67108864
Enable-EventLog "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" 67108864
Enable-EventLog "Microsoft-Windows-Bits-Client/Operational"                           67108864
Enable-EventLog "Microsoft-Windows-CodeIntegrity/Operational"                         67108864
Enable-EventLog "Microsoft-Windows-NTLM/Operational"                                  67108864
Enable-EventLog "Microsoft-Windows-SMBClient/Security"                                67108864
Enable-EventLog "Microsoft-Windows-Windows Defender/Operational"                      134217728
Enable-EventLog "Microsoft-Windows-Kernel-PnP/Configuration"                          67108864
Enable-EventLog "Microsoft-Windows-PrintService/Operational"                          67108864

# DC-specific operational logs
Enable-EventLog "DFS Replication"                                                      134217728

# NOT enabled: Microsoft-Windows-DNS-Server/Analytical. It is an ETW analytic
# channel that logs every DNS query - far higher volume than the dns.log debug
# file that STEP 7 configures and that inputs.conf already monitors. Collecting
# both is duplicate coverage. If you prefer the analytic channel over dns.log
# (Microsoft recommends it on performance grounds), enable it here, add a
# matching stanza to inputs.conf, and drop the [monitor://...dns.log] stanza.

# ADFS (only if ADFS role is present)
$adfsService = Get-Service -Name "adfssrv" -ErrorAction SilentlyContinue
if ($adfsService) {
    Write-Log "ADFS service detected - enabling ADFS logs" "OK"
    Enable-EventLog "AD FS/Admin"           67108864
    # AD FS Tracing/Debug intentionally not enabled: a verbose troubleshooting
    # channel that nothing collects. Enable it by hand when diagnosing ADFS.
} else {
    Write-Log "ADFS service not present - skipping ADFS log enablement" "WARN"
}

Write-Log "Operational log channels enabled." "OK"
}

# ── STEP 6: Firewall Logging ────────────────────────────────────────
Invoke-Step "STEP 6: Windows Firewall Logging" {
try {
    Set-NetFirewallProfile -All -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 32767
    Write-Log "  Firewall logging enabled (all profiles)" "OK"
} catch {
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
    netsh advfirewall set allprofiles logging maxfilesize 32767         | Out-Null
    Write-Log "  Firewall logging enabled via netsh (fallback)" "OK"
}
}

# ── STEP 7: DNS Debug Logging ───────────────────────────────────────
Invoke-Step "STEP 7: DNS Server Debug Logging" {
Write-Log "Source: Configuration Guide sec 3.1.2 - enables dns.log for T1071.004 / DGA detection"

if ($SkipDNSLogging) {
    Write-Log "DNS debug logging skipped (-SkipDNSLogging flag set)." "WARN"
} else {
    $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if ($dnsService) {
        try {
            # Enable all DNS diagnostic categories
            Set-DnsServerDiagnostics -All $true -ErrorAction Stop
            Write-Log "  DNS debug logging enabled via Set-DnsServerDiagnostics" "OK"
            Write-Log "  Log location: $env:SystemRoot\System32\dns\dns.log" "OK"

            # Set DNS log file path and max size
            $dnsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
            Set-RegValue $dnsRegPath "LogFilePath"    "$env:SystemRoot\System32\dns\dns.log" "String"
            Set-RegValue $dnsRegPath "MaximumLogFileSize" 100663296   # 96 MB

            Write-Log "DNS debug logging configured. File: $env:SystemRoot\System32\dns\dns.log" "OK"
            Write-Log "Add monitor stanza for this path in inputs.conf (DC section)." "WARN"
        } catch {
            Write-Log "  DNS cmdlet failed: $_ - trying netsh dns approach" "WARN"
            $r = Invoke-Native "dnscmd.exe" @("/config", "/LogLevel", "0x8100F331")

            if ($r.ExitCode -eq 0) {
                Write-Log "  DNS logging enabled via dnscmd" "OK"
            } else {
                Write-Log "  dnscmd fallback failed (exit $($r.ExitCode)): $($r.Output -join ' ')" "WARN"
            }
        }
    } else {
        Write-Log "DNS Server service not found - this DC may not host the DNS role." "WARN"
    }
}
}

# ── STEP 8: LDAP Channel Binding / Signing Events ──────────────────
Invoke-Step "STEP 8: Enable LDAP Signing / Channel Binding Diagnostic Events" {
Write-Log "Enables Directory Service EIDs 2887, 2888, 2889 (LDAP security posture)"

Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" `
    "16 LDAP Interface Events" 2   # 2 = Basic

Write-Log "  LDAP Interface Events diagnostics set to level 2 (EIDs 2886-2889 will appear in Directory Service log)" "OK"
}

# ── STEP 9: Sysmon ─────────────────────────────────────────────────
Invoke-Step "STEP 9: Sysmon Deployment" {
Write-Log "Source: SwiftOnSecurity sysmon-config, Olaf Hartong sysmon-modular"

if ($SkipSysmon) {
    Write-Log "Sysmon deployment skipped." "WARN"
} else {
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) { $sysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }

    if ($sysmonSvc) {
        Write-Log "Sysmon already installed. Updating config." "WARN"
        if (Test-Path $SysmonConfig) {
            $r = Invoke-Native $SysmonBinary @("-c", $SysmonConfig)
            $r.Output | ForEach-Object { Write-Log "  Sysmon: $_" }

            if ($r.ExitCode -eq 0) {
                Write-Log "Sysmon config updated." "OK"
            } else {
                Write-Log "Sysmon config update FAILED (exit $($r.ExitCode))." "ERROR"
            }
        } else {
            Write-Log "Config not found: $SysmonConfig" "WARN"
        }
    } elseif (Test-Path $SysmonBinary) {
        if (Test-Path $SysmonConfig) {
            $r = Invoke-Native $SysmonBinary @("-accepteula", "-i", $SysmonConfig)
            $r.Output | ForEach-Object { Write-Log "  Sysmon: $_" }

            $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
            if ($svc) { Write-Log "Sysmon installed and running." "OK" }
            else       { Write-Log "Sysmon install FAILED (exit $($r.ExitCode))." "ERROR" }
        } else {
            Write-Log "Sysmon config not found: $SysmonConfig" "WARN"
            Write-Log "Download: https://github.com/SwiftOnSecurity/sysmon-config" "WARN"
        }
    } else {
        Write-Log "Sysmon binary not found: $SysmonBinary" "WARN"
        Write-Log "Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" "WARN"
    }
}
}

# ── STEP 10: Validation ─────────────────────────────────────────────
Invoke-Step "STEP 10: Validation" {
$checks = @(
    @{ Name="Process Creation (Success)";  Cmd={ (Invoke-Native "auditpol.exe" @("/get","/subcategory:Process Creation")).Output -match "Success" } },
    @{ Name="Kerberos Auth Service";       Cmd={ (Invoke-Native "auditpol.exe" @("/get","/subcategory:Kerberos Authentication Service")).Output -match "Success" } },
    @{ Name="Directory Service Changes";   Cmd={ (Invoke-Native "auditpol.exe" @("/get","/subcategory:Directory Service Changes")).Output -match "Success" } },
    @{ Name="Directory Service Access";    Cmd={ (Invoke-Native "auditpol.exe" @("/get","/subcategory:Directory Service Access")).Output -match "Success" } },
    @{ Name="Command-line registry";       Cmd={
        $v = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
            -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
        $v -and $v.ProcessCreationIncludeCmdLine_Enabled -eq 1
    }},
    @{ Name="PS ScriptBlock logging";      Cmd={
        $v = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
            -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        $v -and $v.EnableScriptBlockLogging -eq 1
    }},
    @{ Name="Sysmon service running";      Cmd={
        $s = Get-Service "Sysmon64" -ErrorAction SilentlyContinue
        if (-not $s) { $s = Get-Service "Sysmon" -ErrorAction SilentlyContinue }
        $s -and $s.Status -eq "Running"
    }}
)

foreach ($check in $checks) {
    try {
        $result = & $check.Cmd
        if ($result) { Write-Log "  PASS: $($check.Name)" "OK"   }
        else          { Write-Log "  FAIL: $($check.Name)" "ERROR" }
    } catch {
        Write-Log "  ERROR checking $($check.Name): $_" "WARN"
    }
}
}

# ── DONE ────────────────────────────────────────────────────────────
$hasFailures = $script:FailedSteps.Count -gt 0
$bannerColor = if ($hasFailures) { "Red" } else { "Green" }
$headline    = if ($hasFailures) {
    "  COMPLETED WITH ERRORS - Domain Controller Logging Prerequisites"
} else {
    "  COMPLETED - Domain Controller Logging Prerequisites"
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor $bannerColor
Write-Host $headline -ForegroundColor $bannerColor
Write-Host ("=" * 70) -ForegroundColor $bannerColor
Write-Host ""

if ($hasFailures) {
    Write-Log "$($script:FailedSteps.Count) step(s) failed:" "ERROR"
    foreach ($f in $script:FailedSteps) { Write-Log "  - $f" "ERROR" }
} else {
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

Write-Host "  1. Deploy DC inputs.conf to: $splunkHome\etc\system\local\" -ForegroundColor Yellow
Write-Host "  2. Deploy outputs.conf to: $splunkHome\etc\system\local\" -ForegroundColor Yellow
Write-Host "  3. Restart Splunk UF: Restart-Service SplunkForwarder" -ForegroundColor Yellow
Write-Host "  4. Verify dns.log path in inputs.conf matches: $env:SystemRoot\System32\dns\dns.log" -ForegroundColor Yellow
Write-Host ""

# Exit non-zero when any step failed, so GPO / SCCM / Intune can detect it.
if ($script:FailedSteps.Count -gt 0) {
    exit 1
}

exit 0
