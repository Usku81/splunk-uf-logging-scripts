# Splunk Universal Forwarder — Baseline Logging Prerequisites

Enable the OS-level logging a Splunk Universal Forwarder needs, then deploy a
matching `inputs.conf`. Controls are drawn from NSA, ACSC, CIS, MITRE ATT&CK and
other published baselines — see [Sources](#sources).

The Linux configs go further than "turn everything on": the auditd ruleset is
curated by **signal per byte**, because the stock baseline produces roughly
**1 GB/day from a single idle host**. See [Volume and tuning](#volume-and-tuning).

---

## Quick start

**1. Set your indexer.** Edit `outputs.conf` — without this the UF collects data
and sends it nowhere:

```ini
[tcpout:primary_indexer]
server = <INDEXER_IP>:9997     # ← your indexer hostname or IP
```

**2. Run the script for the platform** (Linux: root; Windows: Administrator,
Domain Admin on a DC):

```bash
sudo bash ubuntu/Enable-LinuxLogging-Ubuntu.sh
sudo bash rhel-centos/Enable-LinuxLogging-RHEL-CentOS.sh
```
```powershell
.\windows-workstation\Enable-WindowsLogging-Workstation.ps1
.\windows-dc\Enable-WindowsLogging-DC.ps1
```

**3. Deploy the configs** and restart the forwarder:

```bash
cp ubuntu/inputs.conf $SPLUNK_HOME/etc/system/local/inputs.conf
cp outputs.conf       $SPLUNK_HOME/etc/system/local/outputs.conf
$SPLUNK_HOME/bin/splunk restart
```
```powershell
Copy-Item .\windows-workstation\inputs.conf "$env:SPLUNK_HOME\etc\system\local\inputs.conf"
Copy-Item .\outputs.conf "$env:SPLUNK_HOME\etc\system\local\outputs.conf"
Restart-Service SplunkForwarder
```

Each script ends with a PASS/FAIL validation block. No reboot needed on any
platform. Create the `windows` and `linux` indexes on your indexer first, or the
forwarded data is dropped.

> **Rolling out a fleet?** Deploy to **one** host, leave it a week, then run the
> byte-attribution command in [Measure your own hosts](#measure-your-own-hosts).
> The top talker is rarely what you expect — on the reference host it was a
> desktop widget at 80% of all audit volume. Tune, *then* roll out.

### Script options

| Linux | Windows |
|---|---|
| `--skip-sysmon` | `-SkipSysmon` |
| `--skip-auditd-rules` — use existing rules | `-SkipDNSLogging` (DC only) |
| `--skip-volume-tuning` — stock ruleset, no curation | `-SysmonBinary <path>` |
| `--splunk-user USER` | `-SysmonConfig <path>` |

---

## Repository structure

```
├── ubuntu/            Enable-LinuxLogging-Ubuntu.sh       + inputs.conf
├── rhel-centos/       Enable-LinuxLogging-RHEL-CentOS.sh  + inputs.conf
├── windows-workstation/  Enable-WindowsLogging-Workstation.ps1 + inputs.conf
├── windows-dc/        Enable-WindowsLogging-DC.ps1        + inputs.conf
├── outputs.conf       Shared — deploy to ALL platforms
└── limits.conf        Optional — only under disk/RAM pressure
```

Run the script first, then copy that folder's `inputs.conf` plus the shared
`outputs.conf` to `$SPLUNK_HOME/etc/system/local/`. Do not rename them.

**Sysmon on Windows** is deployed only if the binary and config sit beside the
`.ps1`: [sysmon64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
and [sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config).
On Linux it is installed from Microsoft's repo automatically.

---

## What gets configured

**Linux** — auditd (curated [Neo23x0](https://github.com/Neo23x0/auditd) ruleset,
pinned to a commit, `RAW` log format, rotation) · rsyslog auth/syslog/cron
routing · persistent journald · SELinux Enforcing check (RHEL) · Sysmon for Linux
(optional) · ACLs granting the UF read access to `audit.log`.

**Windows** — Advanced Audit Policy via `auditpol.exe` · command line in EID 4688
· PowerShell Module (4103) and Script Block (4104) logging · event log sizing
(Security 2 GB) · operational channels (TaskScheduler, WMI-Activity,
TerminalServices, CodeIntegrity, NTLM, SMBClient, Defender…) · firewall logging ·
AppLocker audit mode.

**Domain Controller additions** — Kerberos (4768/4769/4771) · Directory Service
Changes (5136–5141) · DCSync detection (4662) · DS Replication (4932/4933) · DNS
debug logging · LDAP channel binding diagnostics (2886–2889) · ADFS logs.

---

## Verifying

```bash
systemctl status SplunkForwarder            # running?
$SPLUNK_HOME/bin/splunk list forward-server # indexer reachable?
```

Your indexer should appear under **Active forwards**. Under *Configured but
inactive* means port 9997 is unreachable or not enabled on the indexer.

Then in Splunk:

```
index=linux   | stats count by host, sourcetype
index=windows | stats count by host, sourcetype
index=_internal host=<host> | head 50      # if a host is missing
```

Script logs: `/var/log/splunk-prereq-*.log`, `%SystemRoot%\Temp\Enable-WindowsLogging-*.log`.

| Symptom | Likely cause |
|---|---|
| No data from any host | `<INDEXER_IP>` still a placeholder in `outputs.conf` |
| Linux: no `audit.log` data | UF not root, or missing ACL — script Step 7; check `acl` is installed |
| Windows: 4688 has no command line | Registry key not applied — re-run the script |
| Sysmon events missing | Check `Get-Service Sysmon64` |
| Disk filling / RAM spiking | Deploy `limits.conf` — see below |

---

## Volume and tuning

> Applies to the **Linux** scripts and their `inputs.conf`. Windows has not had
> this pass. Rule curation is identical on both distros (auditd rules are
> OS-agnostic); **input** curation deliberately differs — see
> [Ubuntu and RHEL differ](#ubuntu-and-rhel-differ).

The rule is **signal per byte**, not signal alone. A rule that is occasionally
useful but fires constantly costs more than it returns: it buries what matters
and pushes the kernel audit backlog toward dropping events. Everything below was
measured on a reference endpoint against server-like activity, with desktop and
interactive-session noise excluded.

### Keep and pay for: `process_creation`

**71% of all server-like audit bytes**, ~1.4 KB/event — and the single most
valuable rule you have. Keep it **system-wide**.

The common advice is to scope `execve` to `-F auid>=1000`. **Don't.** A process
spawned by a network service has `auid=unset`, not a user ID, so a web shell
running as `www-data` — or anything launched by a compromised daemon — executes
**completely unlogged**. That one flag turns your best source into one that
misses the attacks it exists to catch. Cut elsewhere.

### What the scripts cut

| Change | Measured | Why |
|---|---:|---|
| `log_format = RAW` (was `ENRICHED`) | **−14.5%** | `ENRICHED` appends translated `AUID`/`UID`/`ARCH` after a `0x1d` separator on every record. TA-linux_auditd resolves these at search time, so on a forwarded fleet it costs nothing. Keep `ENRICHED` only for local `ausearch` forensics on hosts whose `/etc/passwd` may change first. |
| `network_socket_created` cut | 3.8% | `socket()` fires on every DNS lookup and HTTP call. A socket with no `connect()` carries no signal, and `connect()` stays covered for IPv4 (`a2=16`) and IPv6 (`a2=28`) — that's where C2 and lateral movement actually show. |
| `file_access` cut | 1.4% | `open()` → `EACCES`/`EPERM`. Benign permission misses; spikes hard when a service lacks a permission. |
| `file_creation`, `file_modification` cut | <0.2% ea. | Same pattern. Cheap when quiet — but a permissions problem on a busy service makes any of them the host's top talker. |
| `perm_mod` narrowed | large, spiky | Was system-wide, firing on every package install and recursive `chown`. Now 8 paths: `/etc`, `/bin`, `/sbin`, `/usr/{bin,sbin}`, `/usr/local/{bin,sbin}`, `/boot`. `/opt` excluded — agents chown themselves on restart. |
| `delete` narrowed | 4.1% | Those 8 paths plus `/var/log`, `/var/spool/cron`. Deletion matters as anti-forensics (T1070), not as users tidying files. |
| Rules for absent software pruned | — | Upstream ships Filebeat/CrowdStrike/VMware rules; `auditctl` validates `-F dir=`, `-F exe=` and `-w` paths and **refuses** them, two error lines each on every load. Pruned generically by path existence, re-evaluated each run, so installing the software and re-running restores them. No coverage lost — they were never in the kernel. |
| Splunk unit's recursive `chown` guarded | ~28% of a restart-heavy window | `splunk enable boot-start` chowns the whole install tree on every start, and the forwarder then ships its own noise. |

**Kept, deliberately** — all low volume, high value: `process_creation`,
`anon_file_create` (memfd, fileless execution T1620), `raw_network_socket_created`
(AF_PACKET, T1040 sniffing), `mount` (T1611), `namespaces`, `network_connect_4`,
`specialfiles`, `power_abuse`, and every `-w` watch on `/etc/passwd`,
`/etc/shadow`, `/etc/sudoers`, cron dirs, systemd units, shell profiles, audit
config and module load/unload. Watches cost nothing until they fire — there is no
volume there to save.

> **Known gap.** auditd cannot watch a path that doesn't exist, so watches on
> `/etc/cron.allow`, `/etc/cron.deny`, `/etc/at.allow`, `/etc/at.deny` never
> load — and those are exactly what an attacker might *create* to control job
> scheduling. This predates the curation and is not introduced by it. To close
> it, create the files empty with correct ownership, or watch creation within
> `/etc` instead of the individual names.

### Ubuntu and RHEL differ

**Ubuntu duplicates; RHEL does not.** Ubuntu's rsyslog writes kernel and cron
events to *both* their own file and `syslog` — measured **20/20 `kern.log` and
17/17 `cron.log` lines already present verbatim in `syslog`**. Collecting both
indexes them twice, so both monitors are `disabled = true` and the script no
longer creates `51-cron.conf`. `auth.log` is the exception (0/20 duplicated) and
stays.

RHEL's defaults already exclude them:

```
*.info;mail.none;authpriv.none;cron.none   /var/log/messages
authpriv.*                                 /var/log/secure
cron.*                                     /var/log/cron
```

`cron.none` and `authpriv.none` mean `/var/log/cron` and `/var/log/secure` are
the **only** copy, and RHEL has no `kern.log` at all. **Both stay enabled** —
disabling them to match Ubuntu would drop cron and authentication logging
outright.

Also disabled on both: web server stanzas (enable per host — they can exceed
every security source combined) and the `lastlog` scripted input (a relative
script path can't resolve from `system/local`; install TA-nix instead).

**Sourcetype changes** — update any saved search keyed on the old values:

| Platform | Was | Now |
|---|---|---|
| Ubuntu | `linux_messages_syslog` (kern/cron) | `syslog` |
| RHEL | `linux_audit` (dnf/yum logs) | `package` |

If you re-enable Ubuntu's `kern.log`/`cron.log`, exclude those facilities from
syslog so you still pay once:
`*.*;auth,authpriv.none;kern.none;cron.none -/var/log/syslog`

### Measure your own hosts

**Tune from measurement, not intuition.** On the reference endpoint the largest
source wasn't a security rule at all — a desktop panel widget polling `ip addr`
once a second, ~80% of all audit bytes. No amount of rule tuning finds that; byte
attribution found it in one command.

```bash
# Audit bytes grouped by the executable that caused them, or by rule key.
audit_top() {   # usage: audit_top exe   |   audit_top key
  awk -v F="${1:-exe}" '
    { n = length($0) + 1
      if (match($0, /audit\([0-9.]+:[0-9]+\)/)) id = substr($0, RSTART, RLENGTH); else id = "?"
      b[id] += n
      if ($0 ~ /^type=SYSCALL/) {
        v = "(none)"
        if (match($0, " " F "=\"[^\"]*\""))
            v = substr($0, RSTART + length(F) + 3, RLENGTH - length(F) - 4)
        g[id] = v } }
    END { for (i in b) { v = (i in g) ? g[i] : "(none)"; a[v] += b[i]; t += b[i] }
          for (v in a) printf "%12d  %5.1f%%  %s\n", a[v], a[v]*100/t, v }
  ' "${2:-/var/log/audit/audit.log}" | sort -rn | head -15
}
```

`audit_top exe` names the offending program; `audit_top key` names the rule to
tune. To decode a noisy pipeline's hex-encoded command lines:

```bash
grep -A6 'exe="/usr/bin/ip"' /var/log/audit/audit.log | grep '^type=PROCTITLE' \
  | grep -oP 'proctitle=\K[0-9A-F]+' | sort | uniq -c | sort -rn | head -5 \
  | while read -r n hex; do printf "%6d  %s\n" "$n" "$(echo "$hex" | xxd -r -p | tr '\0' ' ')"; done
```

Splunk's own view of what it read and shipped:

```bash
grep 'group=thruput, name=thruput' $SPLUNK_HOME/var/log/splunk/metrics.log | tail -5
grep 'group=tcpout_connections'    $SPLUNK_HOME/var/log/splunk/metrics.log | tail -5
```

> Two counting traps. `kbps` in `metrics.log` means kilo**bytes**/sec, not
> kilobits — check it against `total_k_processed ÷ uptime`. And Splunk indexes
> each audit *record* as an event, while auditd emits ~7 records per *event*
> (`SYSCALL` + `EXECVE` + `CWD` + `PATH`×2 + `PROCTITLE`…), so a Splunk event
> count runs ~7× the real audit event count.

### Where filtering can happen

A Universal Forwarder **cannot** filter per event. `props.conf` /
`transforms.conf` → `nullQueue` runs in the parsing pipeline, which a UF doesn't
execute — it ships pre-cooked blocks.

| Approach | Saves license | Saves endpoint disk/CPU/network |
|---|:---:|:---:|
| Filter on the indexer | yes | **no** |
| Convert UF → heavy forwarder | yes | no (costs more) |
| **Tune auditd rules** | yes | **yes** |

That's why all tuning happens at auditd. The UF's only input-side lever is
whole-file `blacklist`/`whitelist` in a `[monitor://]` stanza — files, not events.

**Last resort — suppressing a known-benign process.** Suppression rules go in the
managed block *before* the `always,exit` rules (auditd is first-match, and they
can't live in an earlier-sorting file because the header's `-D` would wipe them):

```
-a never,exit -F arch=b64 -S all -F exe=/usr/bin/ip -F auid=1000
```

Suppressing by `-F exe=` is a real detection gap — anything an attacker can
invoke as that path becomes invisible. Fix the noisy process first.

### Fleet reproducibility and reverting

The ruleset is **pinned to a commit** (`6111069`, 2026-05-04), not `master`.
Rolling hosts out over days while tracking `master` leaves them on silently
different rules, making a later gap impossible to reason about. Bump the pin
deliberately, re-test, redeploy. For hosts without outbound internet, fetch the
pinned ruleset once and place it beside the script as `audit.rules.neo23x0`; it
is used automatically when GitHub is unreachable. It is not shipped in the repo.

Edits land between `## >>> BEGIN volume-tuning (managed) >>>` markers, and
disabled rules are commented rather than deleted. Re-running is idempotent. To
revert by hand:

```bash
sed -i '/^## >>> BEGIN volume-tuning (managed) >>>$/,/^## <<< END volume-tuning (managed) <<<$/d' /etc/audit/rules.d/audit.rules
sed -i 's|^## \[volume-tuning disabled\] ||; s|^## \[volume-tuning absent-path\] ||' /etc/audit/rules.d/audit.rules
augenrules --load
```

---

## Resource impact

**UF baseline:** 100–200 MB RSS, rising to 300–500 MB when the indexer is
unreachable and the queue fills — the usual cause of surprise RAM alerts. That's
what `limits.conf` is for: deploy it only under real pressure, as it caps
outbound throughput (`maxKBps`) and the in-memory queue.

| Source | CPU | RAM | Notes |
|---|:---:|:---:|---|
| Sysmon EID 7 (Image/DLL Load) | High | High | Every DLL load. Heavily filtered in the SwiftOnSecurity config — don't remove those exclusions. |
| Sysmon EID 3 (Network Connection) | High | Medium | Every TCP/UDP connection. |
| auditd `execve` | High | High | Every process execution. The biggest single cost, and worth it — see [Keep and pay for](#keep-and-pay-for-process_creation). Do **not** scope by `auid`. |
| Sysmon EID 1 (Process Create) | Medium | Medium | Duplicates auditd `execve` if both run — pick one. |
| PowerShell Script Block (4104) | Medium | Medium | Cost is in the PS engine, not the UF. |
| Windows Security 4688 | Medium | Low | Native kernel logging; lighter than Sysmon EID 1. |
| auditd `-w` watches | Low | Low | Only fire on actual access. |
| Windows auth (4624/4625) | Low | Low | Higher on DCs. |
| rsyslog / auth.log / secure | Low | Low | Negligible. |

This ranks by **CPU and RAM**. Ranking by *volume* gives a different and more
surprising order — measure it with [`audit_top`](#measure-your-own-hosts).

---

## Reference

**Indexes and sourcetypes** — create `windows` and `linux` before deploying.

| Platform | Index | Key sourcetypes |
|---|---|---|
| Windows | `windows` | `XmlWinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `dns` (DC) |
| Linux | `linux` | `linux_audit`, `linux_secure`, `syslog`, `dpkg` (Ubuntu), `package` (RHEL) |
| Web logs | `linux` | `web_access`, `web_error` |

**Requirements** — Ubuntu 20.04/22.04/24.04 LTS or RHEL 8/9 / CentOS 8 Stream,
run as root. Windows as Administrator, Domain Admin for the DC script. The
[Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html)
is installed separately.

### Sources

| Source | Reference |
|--------|-----------|
| **NSA** | [Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance), *Spotting the Adversary with Windows Event Log Monitoring* |
| **ACSC** | [*Windows Event Logging and Forwarding*](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding) |
| **CISA / ACSC / FBI / NCSC** | [*Best Practices for Event Logging and Threat Detection* (2024)](https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection) |
| **CIS** | [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) §17 — Advanced Audit Policy |
| **MITRE ATT&CK** | [M1047](https://attack.mitre.org/mitigations/M1047/), T1059, T1053, T1136, T1098, T1548, T1071, T1110 |
| **Microsoft** | [Appendix L — Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor), [Audit Policy Recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) |
| **JSCU-NL** | [logging-essentials](https://github.com/JSCU-NL/logging-essentials) |
| **Palantir** | [windows-event-forwarding](https://github.com/palantir/windows-event-forwarding) |
| **Mandiant** | [*Greater Visibility Through PowerShell Logging*](https://cloud.google.com/blog/topics/threat-intelligence/greater-visibility/) |
| **TrustedSec** | [Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide) |
| **Neo23x0** | [auditd ruleset](https://github.com/Neo23x0/auditd) |
| **SwiftOnSecurity** | [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) · **Olaf Hartong** [sysmon-modular](https://github.com/olafhartong/sysmon-modular) |
| **Microsoft MSTIC** | [Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux), [MSTIC-Sysmon](https://github.com/Azure/MSTIC-Sysmon) |
| **Splunk** | [TA-linux_auditd](https://splunkbase.splunk.com/app/4232) · [TA-nix](https://splunkbase.splunk.com/app/833) |
