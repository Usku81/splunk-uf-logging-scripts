# Splunk Universal Forwarder — Baseline Logging Prerequisites

Scripts to enable all logging prerequisites on Linux and Windows systems before deploying a Splunk Universal Forwarder. Each script implements the baseline logging configurations recommended by the NSA, ACSC, CIS, MITRE ATT&CK, and other authoritative security frameworks.

---

## Scripts

| Script | Platform | Purpose |
|--------|----------|---------|
| `Enable-LinuxLogging-Ubuntu.sh` | Ubuntu 20.04 / 22.04 LTS | Enables auditd, rsyslog, journald, and Sysmon for Linux |
| `Enable-LinuxLogging-RHEL-CentOS.sh` | RHEL 8/9 / CentOS 8 Stream | Enables auditd, rsyslog, SELinux verification, journald, and Sysmon for Linux |
| `Enable-WindowsLogging-Workstation.ps1` | Windows Workstation / Member Server | Configures audit policies, PowerShell logging, event log sizes, Sysmon, and firewall logging |
| `Enable-WindowsLogging-DC.ps1` | Windows Domain Controller | All workstation settings plus Kerberos, DS Access, DCSync detection, DNS debug logging, and ADFS logs |

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

## Authoritative Sources & Frameworks

These scripts implement controls drawn from the following recognised security baselines:

| Source | Reference |
|--------|-----------|
| **NSA** | Endpoint Forensics Guide (EFG), *Spotting the Adversary* |
| **ACSC** | *Windows Event Logging and Forwarding* |
| **CIS** | CIS Benchmarks §17 — Audit Policy |
| **MITRE ATT&CK** | M1047 (Audit), T1059, T1053, T1136, T1098, T1548, T1071, T1110, and others |
| **Microsoft** | Appendix L — Audit Policy Recommendations |
| **JSCU-NL** | [logging-essentials](https://github.com/JSCU-NL/logging-essentials) |
| **Palantir** | Windows Event Forwarding (WEF) guidance |
| **Mandiant** | *Greater Visibility Through PowerShell Logging* |
| **TrustedSec** | Sysmon Community Guide |
| **Neo23x0** | [auditd best-practice ruleset](https://github.com/Neo23x0/auditd) |
| **SwiftOnSecurity** | [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) |
| **Olaf Hartong** | [sysmon-modular](https://github.com/olafhartong/sysmon-modular) |
| **Microsoft MSTIC** | [Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux) |

---

## Usage

### Linux

```bash
# Ubuntu
sudo bash Enable-LinuxLogging-Ubuntu.sh

# RHEL / CentOS
sudo bash Enable-LinuxLogging-RHEL-CentOS.sh

# Options
--skip-sysmon           Skip Sysmon for Linux installation
--skip-auditd-rules     Use existing auditd rules (skip Neo23x0 download)
--splunk-user USER       Splunk UF run-as user (default: splunk)
```

### Windows (run as Administrator / Domain Admin on DC)

```powershell
# Workstation / Member Server
.\Enable-WindowsLogging-Workstation.ps1

# Domain Controller
.\Enable-WindowsLogging-DC.ps1

# Options
-SkipSysmon             Skip Sysmon deployment
-SkipDNSLogging         Skip DNS debug logging (DC only)
-SysmonBinary <path>    Path to sysmon64.exe (default: .\sysmon64.exe)
-SysmonConfig <path>    Path to Sysmon XML config (default: .\sysmonconfig-export.xml)
```

After running a script, deploy `inputs.conf` and `outputs.conf` to `$SPLUNK_HOME/etc/system/local/` and restart the Splunk Universal Forwarder.

---

## Requirements

- **Linux scripts**: Run as root (`sudo`). Ubuntu 20.04/22.04 or RHEL 8/9 / CentOS 8 Stream.
- **Windows scripts**: Run as Administrator. Domain Admin required for DC script.
- **Sysmon** (optional): Download [sysmon64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and a config (e.g. [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)) into the same folder before running.
