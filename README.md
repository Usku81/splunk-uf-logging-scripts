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

- **auditd** — installs, enables, and deploys the [Neo23x0 best-practice ruleset](https://github.com/Neo23x0/auditd), tuned with `RAW` log format, log rotation, and [volume tuning](#audit-volume-tuning)
- **rsyslog** — verifies auth logging (`/var/log/auth.log` on Ubuntu, `/var/log/secure` on RHEL/CentOS), syslog, and cron routing. On Ubuntu it retires the duplicate `cron.log` it used to create; on RHEL `/var/log/cron` is the only copy and is left alone.
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
--skip-volume-tuning    Keep the stock Neo23x0 ruleset verbatim
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

The table above ranks sources by *CPU and RAM*. Ranking them by *volume* usually
produces a different and more surprising order — see
[Audit Volume Tuning](#audit-volume-tuning) for how to measure it on your own
hosts rather than guessing.

---

## What to keep and what to cut

> Applies to the **Ubuntu** and **RHEL/CentOS** scripts and their `inputs.conf`.
> The Windows configs have not been through this curation pass yet.
>
> The ruleset curation is identical on both — auditd rules are OS-agnostic. The
> **input** curation is deliberately not: see *Cut at the input layer* below,
> where Ubuntu and RHEL reach opposite conclusions for good reason.

The decision rule is **signal per byte**, not signal alone. A rule that is
occasionally useful but fires constantly costs more than it returns, because it
buries the events you care about and pushes the kernel audit backlog toward
dropping them. Everything below was measured on a reference endpoint against
server-like activity, with desktop and interactive-session noise excluded.

### The one that dominates: `process_creation`

**71% of all server-like audit bytes**, at ~1.4 KB per event. It is also the
single most valuable rule you have — nearly every intrusion involves executing
something. **Keep it, system-wide, and pay for it.**

The common advice is to scope `execve` to `-F auid>=1000`. **Do not.** A process
spawned by a network service has `auid=unset`, not a user ID — so a web shell
running as `www-data`, a compromised systemd unit, or anything launched by a
daemon executes **completely unlogged**. That single flag turns your best
detection source into one that misses the attacks it exists to catch. Cut
elsewhere.

### Cut — low signal per byte

| Rule key | Measured | Why it goes |
|---|---:|---|
| `network_socket_created` | 3.8% | `socket(AF_INET/AF_INET6)` fires on every DNS lookup and HTTP client call. A socket with no `connect()` carries no signal, and `connect()` is separately covered for IPv4 (`a2=16`) and IPv6 (`a2=28`) — that is where the C2 and lateral-movement evidence actually is. |
| `file_access` | 1.4% | `open()` → `EACCES`/`EPERM`. Failed opens by unprivileged users, overwhelmingly benign, and it spikes hard whenever a service is missing a permission. |
| `file_creation` | <0.2% | Same `EACCES`/`EPERM` pattern for create-type calls. |
| `file_modification` | <0.2% | Same pattern for `rename`/`truncate`/`chmod`. |

The last three look cheap in a quiet window. They are cut because of their
behaviour **under load** — a permissions problem on a busy service turns any of
them into the top talker on the host.

### Narrow — right intent, wrong scope

| Rule key | Was | Now | Why |
|---|---|---|---|
| `perm_mod` | system-wide | 8 paths (`/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/{bin,sbin}`, `/boot`) | System-wide it fires on every package install and every recursive `chown`. A permission change matters where it grants privilege or backdoors a binary. `/opt` is deliberately excluded — agent software recursively chowns itself on restart. |
| `delete` | system-wide, 4.1% | 8 paths (above, plus `/var/log`, `/var/spool/cron`) | Deletion matters as anti-forensics (T1070) and persistence tampering, not as a record of users tidying their own files. |

### Keep — these are the point of the exercise

All low volume, all high value. `process_creation`, `anon_file_create`
(`memfd_create`, fileless execution — T1620), `raw_network_socket_created`
(AF_PACKET raw sockets — T1040 sniffing), `mount` (T1611 container escape),
`namespaces`, `network_connect_4`, `specialfiles` (`mknod`), `power_abuse`
(root touching another user's home), plus every `-w` watch on `/etc/passwd`,
`/etc/shadow`, `/etc/sudoers`, cron directories, systemd units, shell profiles,
audit config, and module load/unload.

Watches only fire on actual access, so they cost essentially nothing until they
matter. Never cut these to save volume — there is no volume there to save.

### Cut at the input layer: duplicated files (Ubuntu only)

**This cut applies to Ubuntu and must not be copied to RHEL.** Ubuntu's rsyslog
routes kernel and cron messages into **both** their own file and
`/var/log/syslog`:

```
*.*;auth,authpriv.none      -/var/log/syslog     # includes kern.* and cron.*
kern.*                      -/var/log/kern.log   # the same lines again
cron.*                      -/var/log/cron.log   # the same lines again
```

Measured on a reference host: **20/20 `kern.log` lines and 17/17 `cron.log`
lines were already present verbatim in `syslog`.** Collecting all three indexes
those events twice. Both dedicated monitors are therefore `disabled = true` in
`ubuntu/inputs.conf`, and the script no longer creates `/etc/rsyslog.d/51-cron.conf`.

`auth.log` is the exception and must be collected separately — rsyslog routes
auth *away* from syslog (`auth,authpriv.none`), measured 0/20 duplicated.

**If you re-enable either**, exclude that facility from syslog instead so you
still pay once:

```
*.*;auth,authpriv.none;kern.none;cron.none  -/var/log/syslog
```

**Sourcetype impact:** with these disabled, kernel and cron events arrive as
`sourcetype=syslog` rather than `linux_messages_syslog`. Saved searches and
dashboards keyed on the old sourcetype need updating — the events are still
there.

**RHEL reaches the opposite conclusion.** Its default routing already excludes
cron and authpriv from `messages`, and it has no `kern.log` at all:

```
*.info;mail.none;authpriv.none;cron.none   /var/log/messages
authpriv.*                                 /var/log/secure
cron.*                                     /var/log/cron
```

So `/var/log/cron` and `/var/log/secure` are the **only** copy of those events.
Both stay enabled in `rhel-centos/inputs.conf`. Disabling them to match the
Ubuntu file would lose cron and authentication logging outright.

RHEL got one input fix of its own: `dnf.log`, `dnf.rpm.log` and `yum.log` were
tagged `sourcetype = linux_audit`, which mixed package-manager output into
auditd searches and broke CIM normalization. They are now `package`.

### Reproducible across a fleet

The ruleset is **pinned to a commit** (`6111069`, 2026-05-04), not `master`, and
a vendored copy ships beside the script as a fallback for hosts without outbound
internet. Rolling 70 hosts out over days while tracking `master` means they
silently end up on different rules depending on when each one ran, which makes a
detection gap impossible to reason about afterwards. Bump the pin deliberately,
re-test, redeploy.

Expect a number of rules to be skipped at load time with
`Error sending add rule data request (No such file or directory)`. These are
upstream rules referencing software absent from the host (VMware tools,
CrowdStrike); `auditctl` validates `-F exe=` and `-F dir=` paths and skips the
rule. Harmless, but it means the loaded rule count is lower than the file count.

---

## Audit Volume Tuning

The stock Neo23x0 ruleset is written for coverage, not for cost. On a reference
Ubuntu-family endpoint it produced **~1.08 GB/day of raw audit volume from a
single, largely idle host** — which is what you pay to index, regardless of how
well it compresses in transit.

### What the scripts do automatically

| Change | Measured effect | Flag to opt out |
|---|---|---|
| `log_format = RAW` instead of `ENRICHED` | **−14.5%** | edit `apply_auditd_conf` |
| `perm_mod` narrowed from system-wide to 8 security-relevant paths | large, spiky — it fires on every package install and recursive `chown` | `--skip-volume-tuning` |
| `file_access` (failed `open` → `EACCES`/`EPERM`) disabled | −1.4% steady, higher under load | `--skip-volume-tuning` |
| Splunk unit's recursive `chown` on every start replaced with a guarded check | ~28% of bytes across a restart-heavy window | n/a — only applies if such a unit exists |

`ENRICHED` appends translated `AUID`/`UID`/`ARCH` fields after a `0x1d`
separator on every record. TA-linux_auditd resolves those at search time, so on
a forwarded fleet `RAW` costs you nothing. Keep `ENRICHED` if you rely on local
`ausearch` forensics on hosts whose `/etc/passwd` may change before the logs are
read.

The rule edits are written into `/etc/audit/rules.d/audit.rules` between
`## >>> BEGIN volume-tuning (managed) >>>` markers, and disabled rules are
commented with `## [volume-tuning disabled]` rather than deleted. Re-running the
script is idempotent. To revert by hand:

```bash
sed -i '/^## >>> BEGIN volume-tuning (managed) >>>$/,/^## <<< END volume-tuning (managed) <<<$/d' /etc/audit/rules.d/audit.rules
sed -i 's|^## \[volume-tuning disabled\] ||' /etc/audit/rules.d/audit.rules
augenrules --load
```

### Measuring audit volume

**Tune from measurement, not intuition.** On the reference endpoint the single
largest source was not a security rule at all — it was a desktop panel widget
polling `ip addr` once a second, accounting for ~80% of all audit bytes. No
amount of rule tuning would have found that; byte attribution found it in one
command.

Attribute whole audit events to the executable that caused them:

```bash
awk '
{ n = length($0) + 1
  if (match($0, /audit\([0-9.]+:[0-9]+\)/)) id = substr($0, RSTART, RLENGTH); else id = "?"
  bytes[id] += n
  if ($0 ~ /^type=SYSCALL/) {
      e = "(none)"
      if (match($0, / exe="[^"]*"/)) e = substr($0, RSTART+6, RLENGTH-7)
      ex[id] = e } }
END { for (i in bytes) { e = (i in ex) ? ex[i] : "(no SYSCALL)"; agg[e] += bytes[i]; tot += bytes[i] }
      for (e in agg) printf "%12d  %5.1f%%  %s\n", agg[e], agg[e]*100/tot, e }
' /var/log/audit/audit.log | sort -rn | head -15
```

Same idea, grouped by the rule key that fired — this tells you which rule to tune:

```bash
awk '
{ n = length($0) + 1
  if (match($0, /audit\([0-9.]+:[0-9]+\)/)) id = substr($0, RSTART, RLENGTH); else id = "?"
  bytes[id] += n
  if ($0 ~ /^type=SYSCALL/) {
      k = "(nokey)"
      if (match($0, / key="[^"]*"/)) k = substr($0, RSTART+6, RLENGTH-7)
      ky[id] = k } }
END { for (i in bytes) { k = (i in ky) ? ky[i] : "(no SYSCALL)"; agg[k] += bytes[i]; tot += bytes[i] }
      for (k in agg) printf "%12d  %5.1f%%  %s\n", agg[k], agg[k]*100/tot, k }
' /var/log/audit/audit.log | sort -rn | head -15
```

Identify a noisy pipeline by decoding `PROCTITLE` (hex-encoded command lines):

```bash
grep -A6 'exe="/usr/bin/ip"' /var/log/audit/audit.log \
  | grep '^type=PROCTITLE' | grep -oP 'proctitle=\K[0-9A-F]+' \
  | sort | uniq -c | sort -rn | head -5 \
  | while read -r n hex; do printf "%6d  %s\n" "$n" "$(echo "$hex" | xxd -r -p | tr '\0' ' ')"; done
```

Splunk's own view of what it read and shipped:

```bash
grep 'group=thruput, name=thruput'  $SPLUNK_HOME/var/log/splunk/metrics.log | tail -5
grep 'group=tcpout_connections'     $SPLUNK_HOME/var/log/splunk/metrics.log | tail -5
```

> **Note:** `kbps` in `metrics.log` means **kilo*bytes*** per second, not kilobits.
> Verify against `total_k_processed` divided by uptime before reporting a number.

### Where filtering can and cannot happen

A Universal Forwarder **cannot** do per-event filtering. `props.conf` /
`transforms.conf` → `nullQueue` runs in the parsing pipeline, which a UF does
not execute — it ships pre-cooked blocks. Your options:

| Approach | Saves license | Saves endpoint disk/CPU/network |
|---|:---:|:---:|
| Filter on the indexer | yes | **no** |
| Convert UF → heavy forwarder | yes | no (costs more) |
| **Tune auditd rules** | yes | **yes** |

This is why all tuning above happens at auditd. The UF's only genuine input-side
lever is whole-file `blacklist` / `whitelist` in a `[monitor://]` stanza, which
filters files, not events.

### Suppressing a known-benign noise source

If you cannot remove the noisy process itself, suppression rules go in the
managed block, **before** the `always,exit` rules — auditd is first-match, and
anything placed after them is never reached. They also cannot live in a
separate earlier-sorting file, because the ruleset header's `-D` would wipe them.

```
-a never,exit -F arch=b64 -S all -F exe=/usr/bin/ip -F auid=1000
```

Treat this as a last resort. Suppressing by `-F exe=` is a real detection gap:
anything an attacker can invoke as that path becomes invisible. Fix the noise
source first.

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

- **Linux scripts**: Run as root (`sudo`). Ubuntu 20.04/22.04/24.04 LTS or RHEL 8/9 / CentOS 8 Stream.
- **Windows scripts**: Run as Administrator. Domain Admin required for the DC script.
- **Splunk Universal Forwarder**: Installed separately — download from [splunk.com](https://www.splunk.com/en_us/download/universal-forwarder.html).
- **Sysmon** (optional): See [Before You Begin](#️-before-you-begin).

No reboot is required on any platform — all changes take effect immediately.
