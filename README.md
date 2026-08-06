# Splunk Universal Forwarder — Baseline Logging Prerequisites

Scripts to enable all logging prerequisites on Linux and Windows systems before deploying a Splunk Universal Forwarder. Each folder also includes a ready-to-deploy `inputs.conf` for the Splunk UF — copy it directly to `$SPLUNK_HOME/etc/system/local/inputs.conf` without renaming. Each script and config implements the baseline logging configurations recommended by the NSA, ACSC, CIS, MITRE ATT&CK, and other authoritative security frameworks.

---

## Repository Structure

```
splunk-uf-logging-scripts/
│
├── ubuntu/
│   ├── Enable-LinuxLogging-Ubuntu.sh       # Run first — enables auditd, rsyslog, journald, Sysmon
│   └── inputs.conf                         # Deploy to Splunk UF on Ubuntu hosts
│
├── rhel-centos/
│   ├── Enable-LinuxLogging-RHEL-CentOS.sh  # Run first — enables auditd, rsyslog, SELinux, Sysmon
│   └── inputs.conf                         # Deploy to Splunk UF on RHEL/CentOS hosts
│
├── windows-workstation/
│   ├── Enable-WindowsLogging-Workstation.ps1  # Run first — audit policy, PowerShell, Sysmon, firewall
│   └── inputs.conf                            # Deploy to Splunk UF on workstations/member servers
│
├── windows-dc/
│   ├── Enable-WindowsLogging-DC.ps1        # Run first — all workstation settings + DC-specific
│   └── inputs.conf                         # Deploy to Splunk UF on domain controllers
│
├── outputs.conf                            # Shared — deploy to ALL platforms
└── limits.conf                             # Optional — only if hitting disk/RAM pressure
```

> **Workflow:** Run the script on the endpoint first to enable OS-level logging, then copy the `inputs.conf` from the matching folder and the shared `outputs.conf` to `$SPLUNK_HOME/etc/system/local/` on the Splunk UF.

---

## ⚠️ Before You Begin

**1. Edit `outputs.conf` — this is required.**

Open `outputs.conf` and replace the placeholder with your actual indexer address. Deploying without this step means the UF collects data but sends it nowhere:

```ini
[tcpout:primary_indexer]
server = <INDEXER_IP>:9997     # ← Replace <INDEXER_IP> with your indexer hostname or IP
```

**2. Download Sysmon (optional but recommended).**

The Windows scripts will deploy Sysmon if the binary and config are present in the same folder. Download both before running:

- **Binary:** [sysmon64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) from Sysinternals
- **Config:** [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (`sysmonconfig-export.xml`) — the recommended community baseline

Place both alongside the `.ps1` script, or pass custom paths with `-SysmonBinary` and `-SysmonConfig`. Use `-SkipSysmon` to skip entirely.

On Linux, Sysmon for Linux is installed automatically by the script unless `--skip-sysmon` is passed.

**3. Confirm you have the required privileges.**

- Linux: root (`sudo`)
- Windows workstation/member server: Administrator
- Windows domain controller: Domain Admin

---

## What These Scripts Configure

### Linux (Ubuntu & RHEL/CentOS)

- **auditd** — installs, enables, and deploys the [Neo23x0 best-practice ruleset](https://github.com/Neo23x0/auditd), tuned with `ENRICHED` log format and log rotation
- **rsyslog** — verifies auth logging (`/var/log/auth.log` on Ubuntu, `/var/log/secure` on RHEL/CentOS), syslog, and cron logging
- **journald** — configures persistent storage to survive reboots
- **SELinux** (RHEL/CentOS) — verifies Enforcing mode for AVC denial logging
- **Sysmon for Linux** (optional) — Microsoft MSTIC-based process, network, and file event collection
- **File permissions** — grants Splunk UF user read access to audit and system logs via ACLs

### Windows (Workstation & Domain Controller)

- **Advanced Audit Policy** — configures all recommended subcategories via `auditpol.exe` (Account Logon, Logon/Logoff, Process Creation, Object Access, Policy Change, Privilege Use, System)
- **Domain Controller additions** — Kerberos authentication (EID 4768/4769/4771), Directory Service Changes (EID 5136–5141), DS Access/DCSync detection (EID 4662), DS Replication (EID 4932/4933)
- **Command-line logging** — enables CommandLine field in Event ID 4688
- **PowerShell logging** — Module Logging (EID 4103) and Script Block Logging (EID 4104) for both 64-bit and 32-bit PowerShell
- **Event log sizes** — Security: 2 GB, System: 256 MB, Directory Service (DC): 512 MB
- **Operational log channels** — TaskScheduler, WMI-Activity, TerminalServices, BITS, CodeIntegrity, NTLM, SMBClient, Windows Defender, and more
- **Windows Firewall logging** — blocked and allowed connections across all profiles
- **DNS debug logging** (DC) — enables `dns.log` for DGA and T1071.004 detection
- **LDAP channel binding diagnostics** (DC) — EIDs 2886–2889
- **ADFS logs** (DC, if role present) — AD FS/Admin and AD FS Tracing/Debug
- **Sysmon** (optional) — deployment with SwiftOnSecurity/Olaf Hartong config support
- **AppLocker audit mode** (Workstation) — EIDs 8002/8003/8004/8007

---

## Usage

### Step 1 — Enable OS-level logging

**Linux**

```bash
# Ubuntu
sudo bash ubuntu/Enable-LinuxLogging-Ubuntu.sh

# RHEL / CentOS
sudo bash rhel-centos/Enable-LinuxLogging-RHEL-CentOS.sh

# Options
--skip-sysmon           Skip Sysmon for Linux installation
--skip-auditd-rules     Use existing auditd rules (skip Neo23x0 download)
--splunk-user USER      Splunk UF run-as user (default: splunk)
```

**Windows** (run as Administrator; Domain Admin required on DC)

```powershell
# Workstation / Member Server
.\windows-workstation\Enable-WindowsLogging-Workstation.ps1

# Domain Controller
.\windows-dc\Enable-WindowsLogging-DC.ps1

# Options
-SkipSysmon             Skip Sysmon deployment
-SkipDNSLogging         Skip DNS debug logging (DC only)
-SysmonBinary <path>    Path to sysmon64.exe (default: .\sysmon64.exe)
-SysmonConfig <path>    Path to Sysmon XML config (default: .\sysmonconfig-export.xml)
```

### Step 2 — Deploy Splunk UF configuration

Copy the `inputs.conf` from the matching platform folder and the shared `outputs.conf` to the Splunk UF local directory, then restart the forwarder:

```bash
# Linux
cp ubuntu/inputs.conf $SPLUNK_HOME/etc/system/local/inputs.conf
cp outputs.conf $SPLUNK_HOME/etc/system/local/outputs.conf
$SPLUNK_HOME/bin/splunk restart
```

```powershell
# Windows
Copy-Item .\windows-workstation\inputs.conf "$env:SPLUNK_HOME\etc\system\local\inputs.conf"
Copy-Item .\outputs.conf "$env:SPLUNK_HOME\etc\system\local\outputs.conf"
Restart-Service SplunkForwarder
```

---

## Verifying the Deployment

Each script ends with a validation block that reports PASS/FAIL for every prerequisite. If checks fail, review the script log file:

- **Linux:** `/var/log/splunk-prereq-*.log`
- **Windows:** `%SystemRoot%\Temp\Enable-WindowsLogging-*.log`

### Confirm the UF is running

```bash
# Linux
systemctl status SplunkForwarder
# or
$SPLUNK_HOME/bin/splunk status
```

```powershell
# Windows
Get-Service SplunkForwarder
```

### Confirm the UF can reach the indexer

```bash
# Linux
$SPLUNK_HOME/bin/splunk list forward-server
```

```powershell
# Windows
& "$env:SPLUNK_HOME\bin\splunk.exe" list forward-server
```

Look for your indexer under **Active forwards**. If it appears under **Configured but inactive**, check network connectivity to port 9997 and confirm the receiving port is enabled on the indexer.

### Confirm data is arriving in Splunk

Run these searches in Splunk to verify events are landing:

```
index=windows | stats count by host, sourcetype
index=linux   | stats count by host, sourcetype
```

If a host is missing, check the UF's internal logs on the endpoint:

```
index=_internal host=<your_host> | head 50
```

### Common issues

| Symptom | Likely cause |
|---|---|
| No data from any host | `<INDEXER_IP>` not replaced in `outputs.conf` |
| Linux: no `audit.log` data | UF not running as root, or missing ACL — see script Step 7 |
| Windows: 4688 events have no command line | Registry key not applied — re-run the script |
| Sysmon events missing | Sysmon not installed — check `Get-Service Sysmon64` |
| Disk filling / RAM spiking | See **Optional Tuning** below |

---

## Optional Tuning — `limits.conf`

`limits.conf` at the repo root is **optional**. Deploy it only if you observe disk or RAM pressure on an endpoint — typically when the indexer becomes unreachable and the UF buffers data locally.

```bash
# Linux
cp limits.conf $SPLUNK_HOME/etc/system/local/limits.conf
$SPLUNK_HOME/bin/splunk restart
```

```powershell
# Windows
Copy-Item .\limits.conf "$env:SPLUNK_HOME\etc\system\local\limits.conf"
Restart-Service SplunkForwarder
```

It caps outbound throughput (`maxKBps`) and the in-memory pipeline queue (`maxSize`), preventing unbounded resource growth during indexer outages. Under normal operation with a stable indexer connection, this file is unnecessary.

---

## Resource Impact

Not all log sources cost the same. If you are deploying to resource-constrained endpoints or high-traffic servers, these are the heaviest sources to watch:

| Source | CPU | RAM | Notes |
|---|:---:|:---:|---|
| Sysmon EID 7 (Image/DLL Load) | High | High | Fires on every DLL load. Heavily filtered in the SwiftOnSecurity config — do not remove those exclusions. |
| Sysmon EID 3 (Network Connection) | High | Medium | Every TCP/UDP connection. Noticeable on servers with many concurrent connections. |
| auditd `execve` syscall rules | High | High | Captures every process execution system-wide. Consider scoping to `auid>=1000` on busy servers. |
| Sysmon EID 1 (Process Create) | Medium | Medium | High detection value; volume scales with system activity. |
| PowerShell Script Block (EID 4104) | Medium | Medium | CPU cost is in the PS engine during de-obfuscation, not the UF. |
| Windows Security 4688 | Medium | Low | Native kernel logging — lower overhead than Sysmon EID 1. |
| auditd file watches (`-w` rules) | Low | Low | Only fires on actual file access. |
| Windows auth events (4624/4625) | Low | Low | Low volume on workstations, higher on DCs. |
| rsyslog / auth.log / secure | Low | Low | Negligible overhead. |

**Splunk UF baseline:** typically 100–200 MB RSS. Spikes to 300–500 MB when the indexer is unreachable and the queue is flushing — this is the most common cause of unexpected RAM alerts.

---

## Authoritative Sources & Frameworks

These scripts and configs implement controls drawn from the following recognised security baselines:

| Source | Reference |
|--------|-----------|
| **NSA** | [Event Forwarding Guidance (EFG)](https://github.com/nsacyber/Event-Forwarding-Guidance), *Spotting the Adversary with Windows Event Log Monitoring* |
| **ACSC** | [*Windows Event Logging and Forwarding*](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding) |
| **CISA / ACSC / FBI / NCSC** | [*Best Practices for Event Logging and Threat Detection* (2024)](https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection) |
| **CIS** | [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) §17 — Advanced Audit Policy Configuration |
| **MITRE ATT&CK** | [M1047 (Audit)](https://attack.mitre.org/mitigations/M1047/), T1059, T1053, T1136, T1098, T1548, T1071, T1110, and others |
| **Microsoft** | [Appendix L — Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor), [Audit Policy Recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) |
| **JSCU-NL** | [logging-essentials](https://github.com/JSCU-NL/logging-essentials) |
| **Palantir** | [windows-event-forwarding](https://github.com/palantir/windows-event-forwarding) |
| **Mandiant** | [*Greater Visibility Through PowerShell Logging*](https://cloud.google.com/blog/topics/threat-intelligence/greater-visibility/) |
| **TrustedSec** | [Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide) |
| **Neo23x0** | [auditd best-practice ruleset](https://github.com/Neo23x0/auditd) |
| **SwiftOnSecurity** | [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) |
| **Olaf Hartong** | [sysmon-modular](https://github.com/olafhartong/sysmon-modular) |
| **Microsoft MSTIC** | [Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux), [MSTIC-Sysmon configs](https://github.com/Azure/MSTIC-Sysmon) |

---

## inputs.conf Index & Sourcetype Reference

| Platform | Index | Key Sourcetypes |
|----------|-------|----------------|
| Windows (all) | `windows` | `XmlWinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, etc. |
| Linux (all) | `linux` | `linux_audit`, `linux_secure`, `syslog`, `dpkg` |
| Web access logs (nginx/apache) | `linux` | `web_access` |
| Web error logs (nginx/apache) | `linux` | `web_error` |
| DNS debug log (DC) | `windows` | `dns` |

> Ensure the `windows` and `linux` indexes exist on your indexer before deploying, or the UF will forward data that gets dropped.

---

## Requirements

- **Linux scripts**: Run as root (`sudo`). Ubuntu 20.04/22.04 LTS or RHEL 8/9 / CentOS 8 Stream.
- **Windows scripts**: Run as Administrator. Domain Admin required for the DC script.
- **Splunk Universal Forwarder**: Installed separately — download from [splunk.com](https://www.splunk.com/en_us/download/universal-forwarder.html).
- **Sysmon** (optional): See [Before You Begin](#️-before-you-begin).

No reboot is required on any platform — all changes take effect immediately.
