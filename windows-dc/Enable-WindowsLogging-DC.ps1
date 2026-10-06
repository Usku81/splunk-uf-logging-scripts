#Requires -RunAsAdministrator

#Requires -Version 5.1
<#

.SYNOPSIS

    Logging prerequisites for Splunk UF collection on a Windows Workstation / Member Server,

    with -DryRun, backup and -Rollback.
 
.DESCRIPTION

    Derived from Usku81/splunk-uf-logging-scripts windows-workstation/Enable-WindowsLogging-Workstation.ps1.
 
    FIXES vs. the original

      1. No backtick line continuations anywhere (all multi-line calls use splatting).

         A backtick followed by a space or a blank line ends the command early. That caused

         "Cannot bind argument to parameter 'Path' because it is an empty string" (STEP 2/4),

         the interactive "Path[0]:" prompt in STEP 9, and "'-All' is not recognized" in STEP 6.

      2. Registry written through the .NET API, so the ModuleNames value literally named "*"

         is never treated as a wildcard.

      3. AppLocker: the AppIDSvc service is protected - Set-Service fails with "Access is denied"

         even as admin, and without an AppLocker policy no 8002-8007 events are produced anyway.

         The script now only enables the channels and reports whether a policy exists.

      4. Sysmon paths resolve next to the script (not the current directory). An existing

         Sysmon is left untouched unless -UpdateSysmonConfig, and then the INSTALLED binary

         is used so binary and driver versions match. sysmon64.exe signature is verified.

      5. Event log sizes only grow - a larger existing log is never shrunk.

      6. Audit policy is ADDITIVE by default (never disables). -EnforceBaseline applies the

         original exact baseline (Process Termination off, Sensitive Privilege Use and

         System Integrity Failure-only) and logs every setting it lowers.

      7. Refuses to run on a Domain Controller (use Enable-WindowsLogging-DC-Safe.ps1).
 
    ADDED

      -DryRun     prints every intended change, changes nothing.

      Backup      auditpol, gpresult, firewall profiles, plus state.json of every value changed.

      -Rollback   reverts exactly what one run changed.
 
.PARAMETER DryRun

    Show what would change. Changes nothing (no backup, no state file).

.PARAMETER Rollback

    Path to a state.json from a previous run on THIS host. Reverts that run and exits.

.PARAMETER EnforceBaseline

    Apply the original exact audit baseline, including disabling flags (noise reduction).

.PARAMETER SkipSysmon

    Do not install Sysmon.

.PARAMETER UpdateSysmonConfig

    If Sysmon is already installed, apply -SysmonConfig to it (not reversible by -Rollback).

.PARAMETER SkipModuleLogging

    Do not enable PowerShell module logging (EID 4103).

.PARAMETER DroppedOnly

    Firewall log: dropped packets only (default logs dropped + allowed, as the original).

.PARAMETER Force

    Allow running on a Domain Controller.
 
.EXAMPLE

    .\Enable-WindowsLogging-Workstation-Safe.ps1 -DryRun

    .\Enable-WindowsLogging-Workstation-Safe.ps1

    .\Enable-WindowsLogging-Workstation-Safe.ps1 -DryRun -EnforceBaseline -SkipSysmon

    .\Enable-WindowsLogging-Workstation-Safe.ps1 -Rollback "C:\ProgramData\WinLoggingChange\<run>\state.json"
 
.NOTES

    Exit codes: 0 = success, 1 = one or more steps failed, 2 = pre-flight refused.

    No reboot required.

#>

[CmdletBinding()]

param(

    [switch]$DryRun,

    [string]$Rollback,

    [switch]$EnforceBaseline,

    [switch]$SkipSysmon,

    [switch]$UpdateSysmonConfig,

    [switch]$SkipModuleLogging,

    [switch]$DroppedOnly,

    [string]$SysmonBinary,

    [string]$SysmonConfig,

    [int]$MinFreeSpaceGB = 3,

    [switch]$Force

)
 
Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'
 
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

if (-not $SysmonBinary) { $SysmonBinary = Join-Path $ScriptDir 'sysmon64.exe' }

if (-not $SysmonConfig) { $SysmonConfig = Join-Path $ScriptDir 'sysmonconfig-export.xml' }
 
$RunId     = Get-Date -Format 'yyyyMMdd_HHmmss'

$Mode      = if ($Rollback) { 'rollback' } elseif ($DryRun) { 'dryrun' } else { 'apply' }

$WorkDir   = Join-Path $env:ProgramData "WinLoggingChange\${RunId}_$Mode"

New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null

$LogFile   = Join-Path $WorkDir 'run.log'

$StateFile = Join-Path $WorkDir 'state.json'
 
# ════════════════════════════════════════════════════════════════════

# Helpers

# ════════════════════════════════════════════════════════════════════
 
function Write-Log {

    param([string]$Message, [ValidateSet('INFO','OK','WARN','ERROR','PLAN')][string]$Level = 'INFO')

    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"

    $color = @{ OK = 'Green'; WARN = 'Yellow'; ERROR = 'Red'; PLAN = 'Cyan'; INFO = 'Gray' }[$Level]

    Write-Host $line -ForegroundColor $color

    Add-Content -Path $LogFile -Value $line

}
 
function Write-Section {

    param([string]$Title)

    $bar = '=' * 70

    Write-Host ''; Write-Host $bar -ForegroundColor Cyan; Write-Host " $Title" -ForegroundColor Cyan; Write-Host $bar -ForegroundColor Cyan

    Add-Content -Path $LogFile -Value "`n$bar`n $Title`n$bar"

}
 
function Invoke-Native {

    # Judge success by exit code, not stderr (PS 5.1 wraps stderr in NativeCommandError).

    param([Parameter(Mandatory)][string]$FilePath, [string[]]$Arguments = @())

    $prev = $ErrorActionPreference

    $ErrorActionPreference = 'Continue'

    try {

        $out = & $FilePath @Arguments 2>&1 | ForEach-Object {

            $t = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" }

            $t.Replace([string][char]0, '').Trim()

        } | Where-Object { $_ }

        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = @($out) }

    } finally { $ErrorActionPreference = $prev }

}
 
$script:FailedSteps = @()

function Invoke-Step {

    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][scriptblock]$Body)

    Write-Section $Title

    try { & $Body }

    catch {

        $script:FailedSteps += $Title

        Write-Log "STEP FAILED: $Title" 'ERROR'

        Write-Log "  $($_.Exception.Message)" 'ERROR'

        Write-Log '  Continuing with remaining steps.' 'WARN'

    }

}
 
# ── State (everything needed to roll back) ──────────────────────────

$script:State = [ordered]@{

    Version             = 1

    Computer            = $env:COMPUTERNAME

    StartedUtc          = (Get-Date).ToUniversalTime().ToString('o')

    AuditBackup         = $null

    Registry            = @()

    EventLogs           = @()

    Firewall            = @()

    SysmonInstalled     = $false

    SysmonConfigUpdated = $false

}

function Save-State {

    if ($DryRun) { return }

    $script:State | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8

}
 
# ── Registry (.NET API: no wildcard handling of a value named "*") ──

function Get-RegState {

    param([string]$SubKey, [string]$Name)

    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey)

    if ($null -eq $k) { return [pscustomobject]@{ KeyExisted = $false; ValueExisted = $false; Value = $null; Kind = $null } }

    try {

        $exists = @($k.GetValueNames()) -contains $Name

        [pscustomobject]@{

            KeyExisted   = $true

            ValueExisted = $exists

            Value        = $(if ($exists) { $k.GetValue($Name) } else { $null })

            Kind         = $(if ($exists) { $k.GetValueKind($Name).ToString() } else { $null })

        }

    } finally { $k.Close() }

}
 
function Write-RegValue {

    param([string]$SubKey, [string]$Name, $Value, [string]$Kind)

    $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($SubKey)

    try {

        $typed = if ($Kind -eq 'DWord') { [int]$Value } else { [string]$Value }

        $k.SetValue($Name, $typed, [Microsoft.Win32.RegistryValueKind]$Kind)

    } finally { $k.Close() }

}
 
function Set-RegTracked {

    param([string]$SubKey, [string]$Name, $Value, [ValidateSet('DWord','String')][string]$Kind = 'DWord')

    $display = "HKLM\$SubKey\$Name"

    $cur = Get-RegState $SubKey $Name

    if ($cur.ValueExisted -and "$($cur.Value)" -eq "$Value") { Write-Log "  Unchanged: $display = $Value"; return }

    $prevText = if ($cur.ValueExisted) { "$($cur.Value)" } else { '<not set>' }

    if ($DryRun) { Write-Log "  [DRYRUN] $display : $prevText -> $Value" 'PLAN'; return }
 
    $script:State.Registry += [pscustomobject]@{

        SubKey = $SubKey; Name = $Name; KeyExisted = $cur.KeyExisted

        ValueExisted = $cur.ValueExisted; PreviousValue = $cur.Value; PreviousKind = $cur.Kind

    }

    Save-State

    Write-RegValue $SubKey $Name $Value $Kind

    Write-Log "  Set: $display : $prevText -> $Value" 'OK'

}
 
# ── Audit policy ────────────────────────────────────────────────────

function Get-AuditInclusion {

    param([string]$Subcategory)

    $r = Invoke-Native 'auditpol.exe' @('/get', "/subcategory:$Subcategory", '/r')

    if ($r.ExitCode -ne 0) { throw "auditpol /get failed for '$Subcategory' (exit $($r.ExitCode)): $($r.Output -join ' ')" }

    $row = @($r.Output | ConvertFrom-Csv) | Select-Object -First 1

    if ($null -eq $row) { throw "auditpol returned no data for '$Subcategory'" }

    return [string]$row.'Inclusion Setting'

}
 
function Format-Audit {

    param([bool]$S, [bool]$F)

    if ($S -and $F) { 'Success and Failure' } elseif ($S) { 'Success' } elseif ($F) { 'Failure' } else { 'No Auditing' }

}
 
function Set-AuditTracked {

    # Default: additive (only enables). -EnforceBaseline: exact target, may disable.

    param([string]$Subcategory, [ValidateSet('Success','Failure','SuccessAndFailure','None')][string]$Want)

    try { $cur = Get-AuditInclusion $Subcategory }

    catch { Write-Log "  $($_.Exception.Message)" 'ERROR'; return }
 
    $hasS  = $cur -match 'Success'

    $hasF  = $cur -match 'Failure'

    $wantS = $Want -in 'Success', 'SuccessAndFailure'

    $wantF = $Want -in 'Failure', 'SuccessAndFailure'
 
    if ($EnforceBaseline) { $newS = $wantS; $newF = $wantF }

    else                  { $newS = $hasS -or $wantS; $newF = $hasF -or $wantF }
 
    if ($newS -eq $hasS -and $newF -eq $hasF) { Write-Log "  Unchanged: $Subcategory = $cur"; return }
 
    $lowers = @()

    if ($hasS -and -not $newS) { $lowers += 'Success' }

    if ($hasF -and -not $newF) { $lowers += 'Failure' }

    $newText = Format-Audit $newS $newF

    $note    = if ($lowers) { "  (DISABLES $($lowers -join '+'))" } else { '' }

    $level   = if ($lowers) { 'WARN' } else { 'OK' }
 
    if ($DryRun) { Write-Log "  [DRYRUN] $Subcategory : '$cur' -> '$newText'$note" 'PLAN'; return }
 
    $a = @('/set', "/subcategory:$Subcategory",

           "/success:$(if ($newS) { 'enable' } else { 'disable' })",

           "/failure:$(if ($newF) { 'enable' } else { 'disable' })")

    $r = Invoke-Native 'auditpol.exe' $a

    if ($r.ExitCode -eq 0) { Write-Log "  Audit: $Subcategory : '$cur' -> '$newText'$note" $level }

    else { Write-Log "  FAILED: $Subcategory (exit $($r.ExitCode)) $($r.Output -join ' ')" 'ERROR' }

}
 
# ── Event logs (enable / grow only) ─────────────────────────────────

function Set-EventLogTracked {

    param([string]$LogName, [long]$MinBytes, [switch]$Enable)

    try { $cfg = Get-WinEvent -ListLog $LogName -ErrorAction Stop }

    catch { Write-Log "  Channel not present on this host: '$LogName' - skipped" 'WARN'; return }
 
    $curBytes   = [long]$cfg.MaximumSizeInBytes

    $needSize   = $curBytes -lt $MinBytes

    $needEnable = $Enable -and -not $cfg.IsEnabled

    $curMB = [math]::Round($curBytes / 1MB); $minMB = [math]::Round($MinBytes / 1MB)
 
    if (-not ($needSize -or $needEnable)) {

        Write-Log "  Unchanged: '$LogName' ($curMB MB, enabled=$($cfg.IsEnabled))"; return

    }

    $a = @('sl', $LogName); $desc = @()

    if ($needEnable) { $a += '/e:true'; $desc += 'enable' }

    if ($needSize)   { $a += "/ms:$MinBytes"; $desc += "size $curMB MB -> $minMB MB" }
 
    if ($DryRun) { Write-Log "  [DRYRUN] '$LogName' : $($desc -join ', ')" 'PLAN'; return }
 
    $script:State.EventLogs += [pscustomobject]@{

        LogName = $LogName; PreviousBytes = $curBytes; PreviousEnabled = [bool]$cfg.IsEnabled

        ChangedSize = $needSize; ChangedEnabled = $needEnable

    }

    Save-State

    $r = Invoke-Native 'wevtutil.exe' $a

    if ($r.ExitCode -ne 0) { Write-Log "  Failed '$LogName' (exit $($r.ExitCode)): $($r.Output -join ' ')" 'WARN'; return }
 
    $eff = [long](Get-WinEvent -ListLog $LogName).MaximumSizeInBytes

    if ($needSize -and $eff -lt $MinBytes) {

        Write-Log "  '$LogName' size NOT applied (effective $([math]::Round($eff/1MB)) MB) - overridden by GPO (Event Log Service policy)." 'WARN'

    } else {

        Write-Log "  '$LogName' : $($desc -join ', ')" 'OK'

    }

}
 
# ════════════════════════════════════════════════════════════════════

# ROLLBACK MODE

# ════════════════════════════════════════════════════════════════════

function Invoke-Rollback {

    param([string]$Path)

    if (-not (Test-Path $Path)) { throw "State file not found: $Path" }

    $s = Get-Content -Path $Path -Raw | ConvertFrom-Json

    if ($s.Computer -ne $env:COMPUTERNAME) { throw "State file belongs to '$($s.Computer)', not '$env:COMPUTERNAME'. Refusing." }

    Write-Log "Rolling back run started $($s.StartedUtc) on $($s.Computer)"
 
    Invoke-Step 'ROLLBACK: Sysmon' {

        if ($s.SysmonInstalled) {

            $exe = Join-Path $env:SystemRoot 'Sysmon64.exe'

            if (Test-Path $exe) {

                $r = Invoke-Native $exe @('-u')

                Write-Log "  Sysmon uninstall exit $($r.ExitCode)" $(if ($r.ExitCode -eq 0) { 'OK' } else { 'ERROR' })

            } else { Write-Log "  $exe not found - uninstall Sysmon manually" 'WARN' }

        } elseif ($s.SysmonConfigUpdated) {

            Write-Log '  Sysmon config was updated by that run and cannot be restored automatically.' 'WARN'

            Write-Log '  Re-apply your previous config XML with: Sysmon64.exe -c <previous.xml>' 'WARN'

        } else { Write-Log '  Sysmon was not changed by that run - nothing to do' }

    }
 
    Invoke-Step 'ROLLBACK: Firewall logging' {

        foreach ($f in @($s.Firewall)) {

            $fw = @{

                Profile             = $f.Profile

                PolicyStore         = 'PersistentStore'

                LogBlocked          = $f.LogBlocked

                LogAllowed          = $f.LogAllowed

                LogMaxSizeKilobytes = [uint64]$f.LogMaxSizeKilobytes

                ErrorAction         = 'Stop'

            }

            Set-NetFirewallProfile @fw

            Write-Log "  $($f.Profile): LogBlocked=$($f.LogBlocked) LogAllowed=$($f.LogAllowed) Size=$($f.LogMaxSizeKilobytes)KB" 'OK'

        }

    }
 
    Invoke-Step 'ROLLBACK: Event logs' {

        foreach ($e in @($s.EventLogs)) {

            $a = @('sl', $e.LogName)

            if ($e.ChangedSize)    { $a += "/ms:$($e.PreviousBytes)" }

            if ($e.ChangedEnabled) { $a += '/e:false' }

            $r = Invoke-Native 'wevtutil.exe' $a

            if ($r.ExitCode -eq 0) { Write-Log "  '$($e.LogName)' restored" 'OK' }

            else { Write-Log "  '$($e.LogName)' not restored (exit $($r.ExitCode)) - shrinking may need the log cleared/archived first: $($r.Output -join ' ')" 'WARN' }

        }

    }
 
    Invoke-Step 'ROLLBACK: Registry' {

        $regs = @($s.Registry); [array]::Reverse($regs)

        foreach ($r in $regs) {

            if ($r.ValueExisted) {

                Write-RegValue $r.SubKey $r.Name $r.PreviousValue $r.PreviousKind

                Write-Log "  Restored HKLM\$($r.SubKey)\$($r.Name) = $($r.PreviousValue)" 'OK'

            } else {

                $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($r.SubKey, $true)

                $empty = $false

                if ($k) {

                    try { $k.DeleteValue($r.Name, $false); $empty = ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) }

                    finally { $k.Close() }

                }

                if (-not $r.KeyExisted -and $empty) { [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($r.SubKey, $false) }

                Write-Log "  Removed HKLM\$($r.SubKey)\$($r.Name) (did not exist before)" 'OK'

            }

        }

    }
 
    Invoke-Step 'ROLLBACK: Audit policy' {

        if ($s.AuditBackup -and (Test-Path $s.AuditBackup)) {

            $r = Invoke-Native 'auditpol.exe' @('/restore', "/file:$($s.AuditBackup)")

            Write-Log "  auditpol /restore exit $($r.ExitCode)" $(if ($r.ExitCode -eq 0) { 'OK' } else { 'ERROR' })

        } else { Write-Log "  Audit backup not found: $($s.AuditBackup)" 'ERROR'; throw 'Audit backup missing' }

    }

}
 
# ════════════════════════════════════════════════════════════════════

# START

# ════════════════════════════════════════════════════════════════════

Write-Host ''

Write-Host " Splunk UF Prerequisites - Workstation / Member Server  [mode: $Mode]" -ForegroundColor White

Write-Host " Working folder: $WorkDir" -ForegroundColor Gray
 
if (-not [Environment]::Is64BitProcess) {

    Write-Log 'Run from 64-bit PowerShell (registry redirection would otherwise apply).' 'ERROR'; exit 2

}
 
if ($Rollback) {

    Invoke-Rollback -Path $Rollback

    if ($script:FailedSteps.Count) { Write-Log "Rollback finished with $($script:FailedSteps.Count) failed step(s)." 'ERROR'; exit 1 }

    Write-Log 'Rollback complete. Run gpupdate /force to re-apply any GPO-managed values.' 'OK'; exit 0

}
 
# ── PRE-FLIGHT ──────────────────────────────────────────────────────

Write-Section 'PRE-FLIGHT CHECKS'
 
$role = (Get-CimInstance Win32_ComputerSystem).DomainRole

$roleName = @{ 0 = 'Standalone workstation'; 1 = 'Member workstation'; 2 = 'Standalone server'; 3 = 'Member server'; 4 = 'Backup DC'; 5 = 'Primary DC' }[[int]$role]

if ($role -ge 4) {

    if ($Force) { Write-Log "This is a Domain Controller ($roleName) - continuing because -Force was given." 'WARN' }

    else { Write-Log "This is a Domain Controller ($roleName). Use Enable-WindowsLogging-DC-Safe.ps1, or -Force." 'ERROR'; exit 2 }

} else { Write-Log "Host role: $roleName" 'OK' }
 
$sysDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"

$freeGB = [math]::Round($sysDrive.FreeSpace / 1GB, 1)

if ($freeGB -lt $MinFreeSpaceGB) { Write-Log "Only $freeGB GB free on $env:SystemDrive (need $MinFreeSpaceGB GB). Refusing." 'ERROR'; exit 2 }

Write-Log "Free space on $env:SystemDrive : $freeGB GB" 'OK'
 
Write-Log "Audit mode: $(if ($EnforceBaseline) { 'ENFORCE baseline (may disable existing flags)' } else { 'ADDITIVE (never disables)' })" $(if ($EnforceBaseline) { 'WARN' } else { 'OK' })
 
$gpoAuditCsv = Join-Path $env:SystemRoot 'security\audit\audit.csv'

if ((Test-Path $gpoAuditCsv) -and (@(Get-Content $gpoAuditCsv | Where-Object { $_.Trim() }).Count -gt 1)) {

    Write-Log 'Advanced Audit Policy is applied by GPO on this host. Local audit changes in STEP 1' 'WARN'

    Write-Log 'will be overwritten at the next GPO refresh. Put STEP 1 into the GPO instead.' 'WARN'

} else { Write-Log 'No GPO-delivered Advanced Audit Policy detected.' 'OK' }
 
$sce = Get-RegState 'SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'

if (-not ($sce.ValueExisted -and [int]$sce.Value -eq 1)) {

    Write-Log "'Audit: Force audit policy subcategory settings' is not enabled - legacy category GPO settings" 'WARN'

    Write-Log 'would override subcategory settings. (Not changed by this script.)' 'WARN'

}
 
if ($ScriptDir -match '\\etc\\(system|apps)\\') {

    Write-Log "Script is running from a Splunk config folder ($ScriptDir). Move scripts and Sysmon files to e.g. C:\Tools." 'WARN'

}
 
# ── BACKUP ──────────────────────────────────────────────────────────

if (-not $DryRun) {

    Write-Section 'BACKUP OF CURRENT CONFIGURATION'

    $auditBackup = Join-Path $WorkDir 'auditpol-before.csv'

    $r = Invoke-Native 'auditpol.exe' @('/backup', "/file:$auditBackup")

    if ($r.ExitCode -ne 0 -or -not (Test-Path $auditBackup)) {

        Write-Log "auditpol /backup failed (exit $($r.ExitCode)). Refusing to continue without a rollback point." 'ERROR'; exit 2

    }

    $script:State.AuditBackup = $auditBackup

    Save-State

    Write-Log "Audit policy backup: $auditBackup" 'OK'
 
    try { $null = Invoke-Native 'gpresult.exe' @('/scope', 'computer', '/h', (Join-Path $WorkDir 'gpresult-before.html'), '/f'); Write-Log 'gpresult saved' 'OK' }

    catch { Write-Log "gpresult failed: $($_.Exception.Message)" 'WARN' }

    try { Get-NetFirewallProfile | Format-List * | Out-File (Join-Path $WorkDir 'firewall-before.txt'); Write-Log 'Firewall profiles saved' 'OK' }

    catch { Write-Log "Firewall export failed: $($_.Exception.Message)" 'WARN' }

    Write-Log "Rollback command: .\$(Split-Path -Leaf $PSCommandPath) -Rollback `"$StateFile`"" 'OK'

} else {

    Write-Log 'DRY RUN - no backup taken, nothing will be changed.' 'PLAN'

}
 
# ── STEP 1: Audit policy ────────────────────────────────────────────

Invoke-Step 'STEP 1: Advanced Audit Policy' {

    $plan = @(

        # Account Logon

        @('Credential Validation',            'SuccessAndFailure'),

        @('Other Account Logon Events',       'SuccessAndFailure'),

        # Account Management

        @('User Account Management',          'SuccessAndFailure'),

        @('Security Group Management',        'Success'),

        @('Computer Account Management',      'Success'),

        @('Other Account Management Events',  'Success'),

        # Detailed Tracking

        @('Process Creation',                 'Success'),

        @('Process Termination',              'None'),      # only acted on with -EnforceBaseline

        @('Plug and Play Events',             'Success'),

        @('RPC Events',                       'Success'),

        # Logon/Logoff

        @('Logon',                            'SuccessAndFailure'),

        @('Logoff',                           'Success'),

        @('Special Logon',                    'Success'),

        @('Account Lockout',                  'Failure'),

        @('Other Logon/Logoff Events',        'SuccessAndFailure'),

        # Object Access

        @('File Share',                       'SuccessAndFailure'),

        @('Detailed File Share',              'Failure'),

        @('Other Object Access Events',       'SuccessAndFailure'),

        @('Removable Storage',                'SuccessAndFailure'),

        # Policy Change

        @('Audit Policy Change',              'Success'),

        @('Authentication Policy Change',     'Success'),

        @('MPSSVC Rule-Level Policy Change',  'Success'),

        @('Other Policy Change Events',       'Failure'),

        # Privilege Use  (enforce: Failure-only; 4674 success is high-volume noise)

        @('Sensitive Privilege Use',          'Failure'),

        # System         (enforce: System Integrity Failure-only; 5061 success is noise)

        @('Security State Change',            'Success'),

        @('Security System Extension',        'Success'),

        @('System Integrity',                 'Failure')

    )

    foreach ($p in $plan) { Set-AuditTracked -Subcategory $p[0] -Want $p[1] }

}
 
# ── STEP 2: Command line in 4688 ────────────────────────────────────

Invoke-Step 'STEP 2: Command line in Process Creation events (4688)' {

    Set-RegTracked 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1

}
 
# ── STEP 3: Core log sizes (grow only) ──────────────────────────────

Invoke-Step 'STEP 3: Core event log sizes (increase only)' {

    Set-EventLogTracked 'Security'    2GB

    Set-EventLogTracked 'System'      256MB

    Set-EventLogTracked 'Application' 64MB

}
 
# ── STEP 4: PowerShell logging ──────────────────────────────────────

Invoke-Step 'STEP 4: PowerShell Script Block + Module logging' {

    Set-RegTracked 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'             'EnableScriptBlockLogging' 1

    Set-RegTracked 'SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1

    if ($SkipModuleLogging) {

        Write-Log '  Module logging (4103) skipped (-SkipModuleLogging).'

    } else {

        Set-RegTracked 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'                         'EnableModuleLogging' 1

        Set-RegTracked 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'             '*' '*' -Kind String

        Set-RegTracked 'SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging'             'EnableModuleLogging' 1

        Set-RegTracked 'SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' -Kind String

    }

    Set-EventLogTracked 'Microsoft-Windows-PowerShell/Operational' 256MB

}
 
# ── STEP 5: Operational channels ────────────────────────────────────

Invoke-Step 'STEP 5: Operational log channels (enable / grow only)' {

    Set-EventLogTracked 'Microsoft-Windows-TaskScheduler/Operational'                            128MB -Enable

    Set-EventLogTracked 'Microsoft-Windows-WMI-Activity/Operational'                             128MB -Enable

    Set-EventLogTracked 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'     64MB  -Enable

    Set-EventLogTracked 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' 64MB  -Enable

    Set-EventLogTracked 'Microsoft-Windows-Bits-Client/Operational'                              64MB  -Enable

    Set-EventLogTracked 'Microsoft-Windows-CodeIntegrity/Operational'                            64MB  -Enable

    Set-EventLogTracked 'Microsoft-Windows-NTLM/Operational'                                     64MB  -Enable

    Set-EventLogTracked 'Microsoft-Windows-SMBClient/Security'                                   64MB  -Enable

    Set-EventLogTracked 'Microsoft-Windows-PrintService/Operational'                             64MB  -Enable

    Set-EventLogTracked 'Microsoft-Windows-Kernel-PnP/Configuration'                             64MB  -Enable

    Set-EventLogTracked 'Microsoft-Windows-Windows Defender/Operational'                         128MB -Enable

}
 
# ── STEP 6: Firewall logging ────────────────────────────────────────

Invoke-Step "STEP 6: Windows Firewall logging (dropped$(if (-not $DroppedOnly) { ' + allowed' }))" {

    $targetKB = 32767

    foreach ($p in @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)) {

        $needBlocked = "$($p.LogBlocked)" -ne 'True'

        $needAllowed = (-not $DroppedOnly) -and ("$($p.LogAllowed)" -ne 'True')

        $needSize    = [uint64]$p.LogMaxSizeKilobytes -lt $targetKB

        if (-not ($needBlocked -or $needAllowed -or $needSize)) { Write-Log "  Unchanged: $($p.Name) profile"; continue }
 
        $desc = @()

        if ($needBlocked) { $desc += 'LogBlocked=True' }

        if ($needAllowed) { $desc += 'LogAllowed=True' }

        if ($needSize)    { $desc += "Size $($p.LogMaxSizeKilobytes)KB -> ${targetKB}KB" }

        if ($DryRun) { Write-Log "  [DRYRUN] $($p.Name): $($desc -join ', ')" 'PLAN'; continue }
 
        $script:State.Firewall += [pscustomobject]@{

            Profile = $p.Name; LogBlocked = "$($p.LogBlocked)"; LogAllowed = "$($p.LogAllowed)"

            LogMaxSizeKilobytes = [uint64]$p.LogMaxSizeKilobytes

        }

        Save-State

        $fw = @{ Profile = $p.Name; PolicyStore = 'PersistentStore'; ErrorAction = 'Stop' }

        if ($needBlocked) { $fw['LogBlocked'] = 'True' }

        if ($needAllowed) { $fw['LogAllowed'] = 'True' }

        if ($needSize)    { $fw['LogMaxSizeKilobytes'] = $targetKB }

        Set-NetFirewallProfile @fw

        Write-Log "  $($p.Name): $($desc -join ', ')" 'OK'

    }

    if (-not $DryRun) {

        foreach ($a in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {

            if ("$($a.LogBlocked)" -ne 'True') { Write-Log "  $($a.Name): effective LogBlocked=$($a.LogBlocked) - a GPO overrides the local setting." 'WARN' }

        }

    }

}
 
# ── STEP 7: Sysmon ──────────────────────────────────────────────────

Invoke-Step 'STEP 7: Sysmon' {

    if ($SkipSysmon) { Write-Log 'Skipped (-SkipSysmon).' 'WARN'; return }
 
    $existing = @(Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue)

    if ($existing.Count) {

        $svcName = $existing[0].Name

        if (-not $UpdateSysmonConfig) {

            Write-Log "Sysmon already installed ($svcName, $($existing[0].Status)) - left untouched. Use -UpdateSysmonConfig to apply $SysmonConfig." 'WARN'

            return

        }

        # Use the INSTALLED binary so the config is applied by the matching version.

        $installed = Join-Path $env:SystemRoot "$svcName.exe"

        if (-not (Test-Path $installed)) { throw "Installed Sysmon binary not found: $installed" }

        if (-not (Test-Path $SysmonConfig)) { throw "Sysmon config not found: $SysmonConfig" }

        try { [xml](Get-Content -Path $SysmonConfig -Raw) | Out-Null } catch { throw "Sysmon config is not valid XML: $($_.Exception.Message)" }
 
        if ($DryRun) { Write-Log "  [DRYRUN] would apply $SysmonConfig to existing $svcName (not reversible by -Rollback)" 'PLAN'; return }
 
        $dump = Invoke-Native $installed @('-c')

        $dump.Output | Set-Content -Path (Join-Path $WorkDir 'sysmon-config-before.txt') -Encoding UTF8

        Write-Log "  Current Sysmon config saved (for reference) to sysmon-config-before.txt"

        $script:State.SysmonConfigUpdated = $true

        Save-State

        $r = Invoke-Native $installed @('-c', $SysmonConfig)

        $r.Output | ForEach-Object { Write-Log "  Sysmon: $_" }

        if ($r.ExitCode -eq 0) { Write-Log 'Sysmon config updated.' 'OK' } else { throw "Sysmon config update failed (exit $($r.ExitCode))." }

        return

    }
 
    if (-not (Test-Path $SysmonBinary)) { Write-Log "Sysmon binary not found: $SysmonBinary - skipped (download from Sysinternals)." 'WARN'; return }

    if (-not (Test-Path $SysmonConfig)) { Write-Log "Sysmon config not found: $SysmonConfig - skipped." 'WARN'; return }

    $sig = Get-AuthenticodeSignature -FilePath $SysmonBinary

    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {

        throw "$SysmonBinary is not validly signed by Microsoft (status: $($sig.Status))."

    }

    try { [xml](Get-Content -Path $SysmonConfig -Raw) | Out-Null } catch { throw "Sysmon config is not valid XML: $($_.Exception.Message)" }
 
    if ($DryRun) { Write-Log "  [DRYRUN] would install Sysmon ($SysmonBinary) with $SysmonConfig" 'PLAN'; return }

    $script:State.SysmonInstalled = $true

    Save-State

    $r = Invoke-Native $SysmonBinary @('-accepteula', '-i', $SysmonConfig)

    $r.Output | ForEach-Object { Write-Log "  Sysmon: $_" }

    $svc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue

    if ($svc -and $svc.Status -eq 'Running') { Write-Log 'Sysmon installed and running.' 'OK' }

    else { throw "Sysmon install failed (exit $($r.ExitCode))." }

}
 
# ── STEP 8: AppLocker channels ──────────────────────────────────────

Invoke-Step 'STEP 8: AppLocker log channels (policy itself must come from GPO)' {

    Set-EventLogTracked 'Microsoft-Windows-AppLocker/EXE and DLL'   64MB -Enable

    Set-EventLogTracked 'Microsoft-Windows-AppLocker/MSI and Script' 64MB -Enable
 
    $ruleCollections = -1

    try {

        $x = [xml](Get-AppLockerPolicy -Effective -Xml)

        $ruleCollections = $x.SelectNodes("//RuleCollection[@EnforcementMode and @EnforcementMode!='NotConfigured']").Count

    } catch { }

    $appId = Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue

    $appIdText = if ($appId) { "$($appId.Status)/$($appId.StartType)" } else { 'not present' }
 
    if ($ruleCollections -gt 0) {

        Write-Log "  AppLocker policy present ($ruleCollections rule collection(s)); AppIDSvc = $appIdText" 'OK'

        if ($appId -and $appId.Status -ne 'Running') { Write-Log '  AppIDSvc is not running - set it to Automatic via GPO (System Services).' 'WARN' }

    } else {

        Write-Log "  No AppLocker policy configured - 8002-8007 events will not be generated. AppIDSvc = $appIdText" 'WARN'

        Write-Log '  Deploy an Audit-only AppLocker policy + AppIDSvc Automatic via GPO (the service is protected;' 'WARN'

        Write-Log "  Set-Service fails with 'Access is denied' even as administrator)." 'WARN'

    }

}
 
# ── STEP 9: Validation ──────────────────────────────────────────────

if (-not $DryRun) {

    Invoke-Step 'STEP 9: Validation' {

        $pc = Get-AuditInclusion 'Process Creation'

        Write-Log "  Process Creation audit = $pc" $(if ($pc -match 'Success') { 'OK' } else { 'ERROR' })
 
        $cl = Get-RegState 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'

        Write-Log "  4688 command line = $($cl.Value)" $(if ($cl.ValueExisted -and [int]$cl.Value -eq 1) { 'OK' } else { 'ERROR' })
 
        $sb = Get-RegState 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'

        Write-Log "  Script block logging = $($sb.Value)" $(if ($sb.ValueExisted -and [int]$sb.Value -eq 1) { 'OK' } else { 'ERROR' })
 
        if (-not $SkipModuleLogging) {

            $ml = Get-RegState 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*'

            Write-Log "  Module logging ModuleNames '*' = $($ml.Value)" $(if ($ml.ValueExisted) { 'OK' } else { 'ERROR' })

        }
 
        $sec = Get-WinEvent -ListLog Security

        Write-Log "  Security log max = $([math]::Round($sec.MaximumSizeInBytes/1MB)) MB" 'OK'
 
        $svc = @(Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue) | Select-Object -First 1

        if ($svc) { Write-Log "  Sysmon service $($svc.Name) = $($svc.Status)" $(if ($svc.Status -eq 'Running') { 'OK' } else { 'WARN' }) }

        else { Write-Log '  Sysmon not installed' $(if ($SkipSysmon) { 'INFO' } else { 'WARN' }) }

    }

}
 
# ── DONE ────────────────────────────────────────────────────────────

$failed = $script:FailedSteps.Count -gt 0

$color  = if ($failed) { 'Red' } else { 'Green' }

$head   = if ($failed) { ' COMPLETED WITH ERRORS' } elseif ($DryRun) { ' DRY RUN COMPLETE - nothing was changed' } else { ' COMPLETED' }

Write-Host ''

Write-Host ('=' * 70) -ForegroundColor $color

Write-Host $head -ForegroundColor $color

Write-Host ('=' * 70) -ForegroundColor $color

if ($failed) { $script:FailedSteps | ForEach-Object { Write-Log "  failed: $_" 'ERROR' } }

Write-Log "Log: $LogFile"

if (-not $DryRun) {

    Write-Log "State (rollback point): $StateFile"

    Write-Log "Rollback: .\$(Split-Path -Leaf $PSCommandPath) -Rollback `"$StateFile`""

}

exit $(if ($failed) { 1 } else { 0 })
 
