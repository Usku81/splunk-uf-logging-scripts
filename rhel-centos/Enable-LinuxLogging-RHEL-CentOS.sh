#!/usr/bin/env bash
# =============================================================================
# Enable-LinuxLogging-RHEL-CentOS.sh
#
# PURPOSE  : Enable prerequisite logging for Splunk UF collection — BUDGET
#            PROFILE (~62 MB/host/day, all Linux sources) — on
#            RHEL 8/9 and CentOS 8 Stream.
#
# APPLIES  : - auditd enablement + Neo23x0 ruleset (pinned, with an optional
#              vendored fallback so every host in a fleet gets identical rules)
#            - auditd.conf tuning (RAW format, dedupe, log rotation)
#            - BUDGET PROFILE audit curation, sized from byte attribution on
#              20 production hosts to fit ~62 MB/host/day for ALL Linux sources
#              (baseline was 510-590 MB/host/day of audit.log alone):
#                * daemon executions narrowed to attacker-useful binaries and
#                  writable-directory execution; login sessions kept in full
#                * outbound connect kept for login sessions + reverse-shell tools
#                * PROCTITLE dropped (duplicates EXECVE argv); CWD for daemons
#                * exact (exe, syscall) suppressions for Netdata IPC/eBPF,
#                  dockerd/containerd mknod, and the forwarder reading audit.log
#                * namespaces scoped to unprivileged users + login sessions
#                * /var/lib/docker data watch dropped (/etc/docker kept)
#                * plus the original cuts: file_access/creation/modification,
#                  network_socket_created; perm_mod/delete narrowed to paths
#            - curated syslog feed (/var/log/splunk-syslog.log) via rsyslog;
#              the local syslog files are left untouched
#            - rsyslog verification (/var/log/secure, /var/log/messages)
#            - SELinux verification (Enforcing mode)
#            - journald persistent storage
#            - Sysmon for Linux (opt-in: --with-sysmon)
#            - File permissions for Splunk UF
#
# SOURCES  : Neo23x0/auditd, bfuzzy/auditd-attack, MITRE ATT&CK M1047,
#            Red Hat Security Guide (RHEL 9 Hardening), ACSC,
#            Splunk TA-linux_auditd docs
#
# USAGE    :
#   sudo bash Enable-LinuxLogging-RHEL-CentOS.sh [OPTIONS]
#
#   Options:
#     --full-exec            Keep process_creation system-wide for daemons too
#                            (original behaviour; ~+35 MB/host/day)
#     --full-connect         Keep connect() system-wide (~+50 MB/host/day)
#     --with-sysmon          Install Sysmon for Linux (OFF by default in the
#                            budget profile; its starter config is unfiltered)
#     --skip-auditd-rules    Skip downloading Neo23x0 rules (use existing)
#     --skip-volume-tuning   Install the pinned Neo23x0 ruleset verbatim,
#                            applying no cuts or narrowing (NOT budget-safe)
#     --splunk-user USER     Splunk UF run-as user (default: splunkfwd)
#     --help                 Show this help
#
#   Site suppressions: put '-a never,...' lines in audit.site-suppressions.rules
#   next to this script; they are copied to the top of the managed block.
#
# REQUIREMENTS : RHEL 8/9 or CentOS 8 Stream, run as root / sudo
# =============================================================================

set -euo pipefail

# ── Defaults ───────────────────────────────────────────────────────
SKIP_SYSMON=true            # budget profile: Sysmon is opt-in
FULL_EXEC=false
FULL_CONNECT=false
SKIP_AUDITD_RULES=false
SKIP_VOLUME_TUNING=false
SPLUNK_USER="splunkfwd"
LOG_FILE="/var/log/splunk-prereq-rhel-$(date +%Y%m%d_%H%M%S).log"
# Pinned to a commit, not master. Across a fleet rolled out over days or weeks,
# tracking master means hosts silently end up on different rulesets depending on
# when they happened to run, and a detection gap becomes impossible to reason
# about. Bump this deliberately, re-test, then redeploy.
NEO23X0_RULES_REF="6111069472c26c4120002933b67cef9855dfbad5"   # 2026-05-04
NEO23X0_RULES_URL="https://raw.githubusercontent.com/Neo23x0/auditd/${NEO23X0_RULES_REF}/audit.rules"
# OPTIONAL vendored copy, used when the host has no outbound internet access
# (common for hardened/air-gapped servers) or when GitHub is unreachable.
# Not shipped in the repository by default - to use it, fetch the pinned
# ruleset once and place it next to this script as 'audit.rules.neo23x0'.
VENDORED_RULES="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)/audit.rules.neo23x0"

# ── Colours ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

# ── Parse args ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-sysmon)       SKIP_SYSMON=true        ;;   # default; kept for compatibility
        --with-sysmon)       SKIP_SYSMON=false       ;;
        --full-exec)         FULL_EXEC=true          ;;
        --full-connect)      FULL_CONNECT=true       ;;
        --skip-auditd-rules) SKIP_AUDITD_RULES=true  ;;
        --skip-volume-tuning) SKIP_VOLUME_TUNING=true ;;
        --splunk-user)       SPLUNK_USER="$2"; shift  ;;
        --help)
            awk 'NR>1 && /^# =+$/ {if (++n == 2) exit; next} NR>1 {sub(/^# ?/, ""); print}' "$0"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ── Logging ────────────────────────────────────────────────────────
log()  { local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
         echo -e "${NC}[$ts] [INFO]  $*"          | tee -a "$LOG_FILE"; }
ok()   { local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
         echo -e "${GREEN}[$ts] [OK]    $*${NC}"   | tee -a "$LOG_FILE"; }
warn() { local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
         echo -e "${YELLOW}[$ts] [WARN]  $*${NC}"  | tee -a "$LOG_FILE"; }
err()  { local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
         echo -e "${RED}[$ts] [ERROR] $*${NC}"     | tee -a "$LOG_FILE"; }
section() {
    local line
    line=$(printf '%.0s=' {1..70})
    echo -e "\n${CYAN}${BOLD}${line}${NC}"        | tee -a "$LOG_FILE"
    echo -e "${CYAN}${BOLD}  $*${NC}"             | tee -a "$LOG_FILE"
    echo -e "${CYAN}${BOLD}${line}${NC}\n"        | tee -a "$LOG_FILE"
}

# ── Root check ─────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root (sudo).${NC}"
    exit 1
fi

# ── OS detection ───────────────────────────────────────────────────
OS_ID=$(. /etc/os-release && echo "$ID")
OS_VERSION=$(. /etc/os-release && echo "$VERSION_ID" | cut -d. -f1)
PKG_MGR="dnf"
command -v dnf &>/dev/null || PKG_MGR="yum"

echo ""
echo -e "${BOLD}  Splunk UF Prerequisite — RHEL/CentOS (${OS_ID} ${OS_VERSION})${NC}"
echo -e "  Package manager: ${PKG_MGR}"
echo -e "  Log file: ${LOG_FILE}"
echo ""

# ═══════════════════════════════════════════════════════════════════
# STEP 1: Verify / Install auditd
# ═══════════════════════════════════════════════════════════════════
section "STEP 1: Verify and Enable auditd"
log "Source: MITRE ATT&CK M1047, Red Hat Security Guide, ACSC"
log "Note: auditd is installed by default on RHEL/CentOS — this step verifies and enables."

# 'acl' provides setfacl, used in STEP 7 to grant the UF read access to
# audit.log. It is present on most RHEL installs but absent from some minimal
# and cloud images, and without it the UF silently cannot read the primary
# security log source. Checked independently of auditd: on a host where audit
# is already present, acl may still be missing.
NEEDED=()
rpm -q audit      &>/dev/null || NEEDED+=(audit audit-libs)
rpm -q acl        &>/dev/null || NEEDED+=(acl)

if [[ ${#NEEDED[@]} -gt 0 ]]; then
    log "Installing: ${NEEDED[*]}"
    $PKG_MGR install -y "${NEEDED[@]}"
    ok "Installed: ${NEEDED[*]}"
else
    ok "audit and acl already installed."
fi

if ! command -v setfacl &>/dev/null; then
    warn "setfacl still unavailable — STEP 7 will fall back to group permissions."
fi

systemctl enable auditd
systemctl start auditd
ok "auditd enabled and started."

# Verify running
if systemctl is-active --quiet auditd; then
    ok "auditd is running."
else
    err "auditd failed to start. Check: journalctl -u auditd"
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 2: Deploy Neo23x0 Auditd Rules
# ═══════════════════════════════════════════════════════════════════
section "STEP 2: Deploy auditd Rules (Neo23x0 Best-Practice Baseline)"
log "Source: https://github.com/Neo23x0/auditd"
log "ATT&CK coverage: T1059, T1053, T1136, T1098, T1548, T1547, T1070, T1105, T1110"
log "Alternative: https://github.com/bfuzzy/auditd-attack (MITRE-tagged keys)"

if [[ "$SKIP_AUDITD_RULES" == "true" ]]; then
    warn "Skipping auditd rules download (--skip-auditd-rules)."
else
    # Backup existing rules
    if [[ -f /etc/audit/rules.d/audit.rules ]]; then
        cp /etc/audit/rules.d/audit.rules \
           "/etc/audit/rules.d/audit.rules.bak.$(date +%Y%m%d_%H%M%S)"
        warn "Existing rules backed up."
    fi

    # Also clear any default generated rules
    find /etc/audit/rules.d/ -name "*.rules" -not -name "audit.rules" \
         -exec mv {} {}.disabled \; 2>/dev/null || true

    # Download to a temp file first: writing straight to the live path means a
    # truncated or failed transfer leaves the host with a broken ruleset.
    RULES_TMP=$(mktemp)
    RULES_SRC=""

    log "Fetching pinned ruleset (${NEO23X0_RULES_REF:0:7})..."
    if command -v curl &>/dev/null && \
       curl -fsSL --max-time 30 "$NEO23X0_RULES_URL" -o "$RULES_TMP" 2>/dev/null; then
        RULES_SRC="upstream (pinned ${NEO23X0_RULES_REF:0:7})"
    elif command -v wget &>/dev/null && \
         wget -qT 30 -O "$RULES_TMP" "$NEO23X0_RULES_URL" 2>/dev/null; then
        RULES_SRC="upstream (pinned ${NEO23X0_RULES_REF:0:7})"
    elif [[ -s "$VENDORED_RULES" ]]; then
        cp "$VENDORED_RULES" "$RULES_TMP"
        RULES_SRC="vendored copy (no network)"
        warn "Could not reach GitHub — using the vendored ruleset."
    fi

    # Sanity-check before going live. A captive portal or proxy error page
    # would otherwise be installed as the ruleset.
    if [[ -n "$RULES_SRC" ]] && [[ $(grep -c '^-[aw] ' "$RULES_TMP" || true) -gt 50 ]]; then
        mv "$RULES_TMP" /etc/audit/rules.d/audit.rules
        chmod 640 /etc/audit/rules.d/audit.rules
        chown root:root /etc/audit/rules.d/audit.rules
        ok "Ruleset installed from ${RULES_SRC}."
    else
        rm -f "$RULES_TMP"
        if [[ -f /etc/audit/rules.d/audit.rules ]]; then
            warn "Could not obtain a valid ruleset — keeping the existing one."
        else
            err "Could not obtain a ruleset and none is present."
            err "  Place one at /etc/audit/rules.d/audit.rules and re-run."
        fi
    fi
fi

# ── Volume tuning: BUDGET PROFILE ─────────────────────────────────
# Runs after the download, because the download overwrites any edits.
#
# BUDGET: 4.2 GB/day for 69 hosts = ~62.3 MB/host/day, ALL Linux sources.
# Baseline before this profile: 510-590 MB/host/day of audit.log alone,
# measured across 20 production hosts (Splunk license_usage + per-record
# byte attribution, Oct 2026). Every cut below is sized from that data.
#
# Measured composition of the baseline audit bytes, per host per day:
#   process_creation  ~300 MB  (58%)  59% of it was Netdata polling:
#                                     tc ~1.5/s, ndsudo->chronyc ~1/s
#   network_connect_4  ~73 MB  (15%)  long-running daemons (haproxy,
#                                     beats, app runtimes) re-connecting
#   docker watch       ~26 MB   (5%)  container apps writing into
#                                     /var/lib/docker (mongod, java)
#   namespaces         ~25 MB   (5%)  98% runc entering container ns
#   IPC                ~22 MB   (4%)  100% Netdata shmget/semctl
#   specialfiles       ~18 MB   (4%)  97% dockerd mknod (overlay whiteouts)
#   bpf                ~18 MB   (4%)  100% Netdata eBPF plugins
#   other               ~20 MB
# Record types: PROCTITLE was 17% of all bytes and duplicates EXECVE's argv
# for every execve event.
#
# Projected after this profile (same hosts, same window): ~51 MB/host/day
# of audit as an UPPER bound (container-internal shells counted as kept;
# they are in fact dropped, see POLICY 1). Plus ~3-5 MB curated syslog and
# <0.5 MB auth/package logs. Re-measure after rollout - see README.
#
# POLICY 1 - process execution (process_creation)
#   Kept in full for every process with a login identity (auid set): SSH,
#   console, sudo/su from a session, and cron jobs (pam_loginuid sets auid).
#   For daemon-spawned processes (auid unset) only the executions an
#   attacker needs are kept:
#     * host shells, network tools, interpreters, encoders, account,
#       scheduling, module, compiler and capture tools (LOLBIN list below)
#     * ANY binary executed from a user-writable or staging directory
#       (/tmp, /var/tmp, /dev/shm, /home, /root, /run/user, /var/www, /srv)
#     * every 32-bit execution (only the b64 path is narrowed)
#   A web shell (www-data -> sh -c '...') stays fully visible: sh is on the
#   list and its EXECVE record carries the whole command string. What is
#   dropped is the routine fan-out of service binaries (tc, chronyc, runc,
#   rpm, docker CLI polling, pg_isready...) and processes inside container
#   images: -F exe= matches the HOST inode, so a container's own /bin/sh is
#   not on the list. That is the main detection gap of this profile -
#   see the README section "What the budget profile gives up".
#   --full-exec restores the original system-wide rule (~+35 MB/host/day).
#
# POLICY 2 - outbound connect (network_connect_4 / _6)
#   Kept for every login-identity process, plus shells, netcat variants,
#   socat, telnet and perl from ANY context (reverse shells). Long-running
#   daemon connects are dropped - perimeter firewall logs (Check Point)
#   already carry the cross-segment flows. --full-connect restores it.
#
# POLICY 3 - container and agent noise, by exact (exe, syscall) pairs
#   Netdata IPC/eBPF, dockerd/containerd mknod, and the Splunk forwarder
#   reading /var/log/audit. These are agents doing their documented job.
#   An exe= suppression is a gap for that one binary only; the binaries
#   live under /usr, which the usr_writes rule still watches for tampering.
tune_audit_volume() {
    local RULES="${1:-/etc/audit/rules.d/audit.rules}"
    local BEG="## >>> BEGIN volume-tuning (managed) >>>"
    local END="## <<< END volume-tuning (managed) <<<"
    local OFF="## [volume-tuning disabled] "
    local SITE_FILE
    SITE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)/audit.site-suppressions.rules"

    if [[ ! -f "$RULES" ]]; then
        warn "No ruleset at $RULES — skipping volume tuning."
        return 0
    fi

    # ── 0. Idempotent reset ───────────────────────────────────────
    sed -i "/^${BEG}\$/,/^${END}\$/d" "$RULES"
    sed -i -e 's|^## \[volume-tuning disabled\] ||' \
           -e 's|^## \[volume-tuning absent-path\] ||' "$RULES"

    if ! grep -q '^-a always,exit' "$RULES"; then
        warn "No 'always,exit' rule found — skipping volume tuning."
        return 0
    fi

    # Comment out every -a/-w line carrying a given key ("-k K" or "-F key=K").
    _off_key() {
        sed -i -E "s@^(-[aw] .*(-k |-F key=)${1})[[:space:]]*\$@${OFF}\1@" "$RULES"
    }
    # Resolve a command to its real path (exe= compares the real inode).
    _real_cmd() {
        local c
        c=$(command -v -- "$1" 2>/dev/null) || return 1
        [[ "$c" == /* && -x "$c" ]] || return 1
        readlink -f -- "$c"
    }
    _first_real() {
        local p
        for p in "$@"; do [[ -x "$p" ]] && { readlink -f -- "$p"; return 0; }; done
        return 1
    }

    # ── 1. Rule families cut outright ─────────────────────────────
    #   file_access / file_creation / file_modification   EACCES/EPERM noise
    #   network_socket_created   socket() with no connect() carries no signal
    #   unauthedfileaccess_system   daemon EACCES on open(): rpm and Netdata
    #                               were 95% of it. Same reasoning as
    #                               file_access, applied to auid=unset.
    local k
    for k in file_access file_creation file_modification \
             network_socket_created unauthedfileaccess_system; do
        _off_key "$k"
    done

    # ── 2. Families rebuilt in the managed block ──────────────────
    # (originals commented out here, scoped versions emitted below)
    for k in perm_mod delete namespaces docker auditlog sharedmemaccess; do
        _off_key "$k"
    done
    if [[ "$FULL_CONNECT" != "true" ]]; then
        _off_key network_connect_4
        _off_key network_connect_6
    fi
    local n_off
    n_off=$(grep -c "^## \[volume-tuning disabled\]" "$RULES" || true)

    # ── 3. Build the managed block ────────────────────────────────
    local PERM="-S chmod -S fchmod -S fchmodat -S chown -S fchown -S fchownat -S lchown"
    PERM="${PERM} -S setxattr -S lsetxattr -S fsetxattr"
    PERM="${PERM} -S removexattr -S lremovexattr -S fremovexattr"
    local DEL="-S rmdir -S unlink -S unlinkat -S rename -S renameat -S renameat2"
    local EXEC="-S execve -S execveat"
    local NS="-S unshare -S setns -S pivot_root"
    local PERM_DIRS=(/etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /boot)
    local DEL_DIRS=(/etc /bin /sbin /usr/bin /usr/sbin /boot /var/log /var/spool/cron)
    local EXEC_DIRS=(/tmp /var/tmp /dev/shm /home /root /run/user /var/www /srv)

    # Attacker-useful binaries. Resolved per host; absent ones are skipped.
    local LOLBIN_CMDS=(
        bash sh dash zsh ksh mksh busybox
        curl wget nc ncat netcat socat telnet ssh scp sftp ftp tftp
        perl php ruby node lua
        base64 xxd openssl gpg
        useradd userdel usermod groupadd groupdel groupmod passwd chpasswd
        chage gpasswd newusers visudo
        crontab at batch sudo su pkexec
        insmod rmmod modprobe chattr setfacl mkfifo
        id whoami uname ssh-keygen
        gcc cc g++ make tcpdump nmap iptables nft
    )
    # Binaries whose connect() is kept from any context (reverse shells).
    local REVSHELL_CMDS=(bash sh dash zsh ksh mksh busybox nc ncat netcat socat telnet perl)

    local -A SEEN=()
    local LOLBINS=() REVSHELL=() c r p
    for c in "${LOLBIN_CMDS[@]}"; do
        r=$(_real_cmd "$c") || continue
        [[ -n "${SEEN[$r]:-}" ]] && continue
        SEEN[$r]=1; LOLBINS+=("$r")
    done
    # Versioned interpreters (python3.9, python3.12, php8.1...) - each is a
    # distinct inode, so each needs its own rule.
    for p in /usr/bin/python[0-9]* /usr/local/bin/python[0-9]* /usr/bin/php[0-9]*; do
        [[ -f "$p" && -x "$p" ]] || continue
        [[ "$(basename "$p")" =~ ^(python|php)[0-9.]+$ ]] || continue
        r=$(readlink -f -- "$p")
        [[ -n "${SEEN[$r]:-}" ]] && continue
        SEEN[$r]=1; LOLBINS+=("$r")
    done
    SEEN=()
    for c in "${REVSHELL_CMDS[@]}"; do
        r=$(_real_cmd "$c") || continue
        [[ -n "${SEEN[$r]:-}" ]] && continue
        SEEN[$r]=1; REVSHELL+=("$r")
    done

    # Agent binaries for POLICY 3.
    local NETDATA_BIN NETDATA_EBPF=() DOCKER_RT=() SPLUNKD d
    NETDATA_BIN=$(_first_real /usr/sbin/netdata /opt/netdata/bin/netdata \
                              /opt/netdata/usr/sbin/netdata) || NETDATA_BIN=""
    for d in /usr/libexec/netdata/plugins.d /usr/lib/netdata/plugins.d \
             /opt/netdata/usr/libexec/netdata/plugins.d; do
        for p in ebpf.plugin ebpf-go.plugin; do
            [[ -x "$d/$p" ]] && NETDATA_EBPF+=("$(readlink -f -- "$d/$p")")
        done
    done
    for c in dockerd containerd; do
        r=$(_real_cmd "$c") && DOCKER_RT+=("$r")
    done
    SPLUNKD=$(_first_real /opt/splunkforwarder/bin/splunkd /opt/splunk/bin/splunkd) || SPLUNKD=""

    local BLK N_ADD=0 a n_site=0 line
    BLK=$(mktemp)
    _r() { echo "$*"; N_ADD=$((N_ADD + 1)); }
    {
        echo "$BEG"
        echo "## BUDGET PROFILE - generated $(date '+%Y-%m-%d %H:%M') by $(basename "$0")"
        echo "## Do not edit inside this block: it is rebuilt on every run."
        echo "## Site-specific suppressions belong in audit.site-suppressions.rules"
        echo "## next to the script (lines starting '-a never,' are copied here)."
        echo ""

        # Site suppressions first: auditd is first-match.
        if [[ -f "$SITE_FILE" ]]; then
            echo "## -- site suppressions (${SITE_FILE##*/}) --"
            while IFS= read -r line; do
                [[ "$line" =~ ^-a\ never, ]] || continue
                _r "$line"; n_site=$((n_site + 1))
            done < "$SITE_FILE"
            echo ""
        fi

        echo "## -- record-type exclusions --"
        echo "## PROCTITLE duplicates EXECVE argv on every exec (17% of bytes)."
        _r "-a always,exclude -F msgtype=PROCTITLE"
        echo "## CWD dropped for daemons only; kept for login sessions, where a"
        echo "## human's relative paths need it. Kernels/auditctl that reject"
        echo "## fields on the exclude list skip this line (-i) and keep CWD."
        _r "-a always,exclude -F msgtype=CWD -F auid=unset"
        echo ""

        echo "## -- agent noise, exact (exe, syscall) pairs --"
        if [[ -n "$NETDATA_BIN" ]]; then
            for a in b64 b32; do
                _r "-a never,exit -F arch=${a} -S msgctl -S msgget -S semctl -S semget -S shmctl -S shmget -F exe=${NETDATA_BIN}"
            done
        fi
        for p in ${NETDATA_EBPF+"${NETDATA_EBPF[@]}"}; do
            _r "-a never,exit -F arch=b64 -S bpf -F exe=${p}"
        done
        for p in ${DOCKER_RT+"${DOCKER_RT[@]}"}; do
            _r "-a never,exit -F arch=b64 -S mknod -S mknodat -F exe=${p}"
        done
        if [[ -n "$SPLUNKD" ]]; then
            echo "## The forwarder tailing audit.log tripped the auditlog watch on every read."
            for a in b64 b32; do
                _r "-a never,exit -F arch=${a} -F dir=/var/log/audit/ -F exe=${SPLUNKD}"
            done
        fi
        _r "-w /var/log/audit/ -p wra -k auditlog"
        echo ""

        echo "## -- execution from writable / staging directories (any context) --"
        echo "## Must precede the /dev/shm suppression re-added just below."
        for d in "${EXEC_DIRS[@]}"; do
            [[ -d "$d" ]] || continue
            for a in b64 b32; do
                _r "-a always,exit -F arch=${a} ${EXEC} -F dir=${d} -k process_creation"
            done
        done
        echo "## upstream /dev/shm high-volume filter, moved below the exec rule"
        for a in b32 b64; do
            _r "-a never,exit -F arch=${a} -F dir=/dev/shm/ -F key=sharedmemaccess"
        done
        echo ""

        if [[ "$FULL_EXEC" != "true" ]]; then
            echo "## -- POLICY 1: daemon executions limited to attacker-useful binaries --"
            for p in ${LOLBINS+"${LOLBINS[@]}"}; do
                _r "-a always,exit -F arch=b64 ${EXEC} -F exe=${p} -k process_creation"
            done
            echo "## everything else exec'd outside a login session (b64 only; the"
            echo "## stock rule further down still logs all auid-set and all b32 execs)"
            _r "-a never,exit -F arch=b64 ${EXEC} -F auid=unset"
            echo ""
        fi

        echo "## -- perm_mod / delete: security-relevant paths only --"
        for d in "${PERM_DIRS[@]}"; do
            [[ -d "$d" ]] || continue
            for a in b64 b32; do
                _r "-a always,exit -F arch=${a} ${PERM} -F dir=${d} -F auid>=1000 -F auid!=unset -k perm_mod"
            done
        done
        for d in "${DEL_DIRS[@]}"; do
            [[ -d "$d" ]] || continue
            for a in b64 b32; do
                _r "-a always,exit -F arch=${a} ${DEL} -F dir=${d} -F auid>=1000 -F auid!=unset -k delete"
            done
        done
        echo ""

        echo "## -- namespaces: unprivileged (userns privesc) and login sessions --"
        echo "## runc/containerd entering container namespaces as root was 98%."
        for a in b64 b32; do
            _r "-a always,exit -F arch=${a} ${NS} -F uid!=0 -k namespaces"
            _r "-a always,exit -F arch=${a} ${NS} -F auid!=unset -k namespaces"
        done
        echo ""

        if [[ "$FULL_CONNECT" != "true" ]]; then
            echo "## -- POLICY 2: outbound connect --"
            for a in b64 b32; do
                _r "-a always,exit -F arch=${a} -S connect -F a2=16 -F success=1 -F auid!=unset -k network_connect_4"
                _r "-a always,exit -F arch=${a} -S connect -F a2=28 -F success=1 -F auid!=unset -k network_connect_6"
            done
            for p in ${REVSHELL+"${REVSHELL[@]}"}; do
                _r "-a always,exit -F arch=b64 -S connect -F a2=16 -F success=1 -F exe=${p} -k network_connect_4"
                _r "-a always,exit -F arch=b64 -S connect -F a2=28 -F success=1 -F exe=${p} -k network_connect_6"
            done
            echo ""
        fi

        echo "## -- container config only (data dir watch dropped) --"
        _r "-w /etc/docker -p wa -k docker"
        echo ""
        echo "$END"
    } > "$BLK"

    awk -v blk="$BLK" '
        !spliced && /^-a always,exit/ {
            while ((getline l < blk) > 0) print l
            close(blk); spliced = 1
        }
        { print }
    ' "$RULES" > "${RULES}.tmp" && mv "${RULES}.tmp" "$RULES"
    rm -f "$BLK"

    # ── 4. Prune rules referencing paths absent on this host ──────
    # auditctl refuses -w, -F dir= and -F exe= on a missing path, two error
    # lines per rule on every load. Re-evaluated each run, so installing the
    # software and re-running restores its rules. No coverage is lost: the
    # kernel had already refused them.
    local PRUNED=0 line keep paths
    : > "${RULES}.tmp"
    while IFS= read -r line; do
        keep=1
        if [[ "$line" == -a\ * || "$line" == -w\ * ]]; then
            paths=()
            [[ "$line" == -w\ * ]] && paths+=("$(printf '%s' "$line" | awk '{print $2}')")
            if [[ "$line" == *" -F dir="* ]]; then p=${line#*-F dir=}; paths+=("${p%% *}"); fi
            if [[ "$line" == *" -F exe="* ]]; then p=${line#*-F exe=}; paths+=("${p%% *}"); fi
            for p in ${paths+"${paths[@]}"}; do
                [[ "$p" == /* ]] || continue
                if [[ ! -e "${p%/}" ]]; then keep=0; break; fi
            done
        fi
        if (( keep )); then
            printf '%s\n' "$line" >> "${RULES}.tmp"
        else
            printf '## [volume-tuning absent-path] %s\n' "$line" >> "${RULES}.tmp"
            PRUNED=$((PRUNED + 1))
        fi
    done < "$RULES"
    mv "${RULES}.tmp" "$RULES"
    chmod 640 "$RULES"; chown root:root "$RULES"

    ok "Budget profile: disabled ${n_off} stock rule(s), added ${N_ADD} managed rule(s)."
    log "  LOLBIN exec exceptions: ${#LOLBINS[@]}   reverse-shell connect rules: ${#REVSHELL[@]}"
    [[ -n "$NETDATA_BIN" ]] && log "  Netdata detected — IPC/eBPF suppressions added for its own binaries."
    [[ ${#DOCKER_RT[@]} -gt 0 ]] && log "  Container runtime detected — mknod suppression added for dockerd/containerd."
    (( n_site > 0 )) && log "  Site suppressions applied: ${n_site}"
    [[ "$FULL_EXEC" == "true" ]]    && warn "  --full-exec: daemon executions NOT narrowed (~+35 MB/host/day)."
    [[ "$FULL_CONNECT" == "true" ]] && warn "  --full-connect: daemon connects NOT narrowed (~+50 MB/host/day)."
    (( PRUNED > 0 )) && log "  Pruned ${PRUNED} rule(s) referencing paths not present on this host."
    return 0
}

if [[ "$SKIP_VOLUME_TUNING" == "true" ]]; then
    warn "Skipping audit volume tuning (--skip-volume-tuning)."
else
    tune_audit_volume
fi

# Load rules
log "Loading auditd rules via augenrules..."
augenrules --load 2>&1 | tee -a "$LOG_FILE" || true
service auditd restart 2>&1 | tee -a "$LOG_FILE" || systemctl restart auditd || true

RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l || echo 0)
if [[ "$RULE_COUNT" -gt 10 ]]; then
    ok "Auditd rules loaded. Active rule count: $RULE_COUNT"
else
    warn "Rule count low ($RULE_COUNT) — check: auditctl -l"
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 3: Tune auditd.conf
# ═══════════════════════════════════════════════════════════════════
section "STEP 3: Tune /etc/audit/auditd.conf"
log "Setting log_format=RAW, rotation, and disk-space thresholds"

AUDITD_CONF="/etc/audit/auditd.conf"

# Repair damage from earlier revisions of this script, which matched keys with
# an unanchored "^${key}" and so let a short key clobber a longer one sharing
# its prefix: applying max_log_file rewrote max_log_file_action as well, which
# then got re-appended, duplicating settings on every run. Collapse any such
# duplicates to their last value before applying the desired config.
dedupe_auditd_conf() {
    [[ -f "$AUDITD_CONF" ]] || return 0
    local before after
    before=$(grep -cE '^[[:space:]]*[A-Za-z_]+[[:space:]]*=' "$AUDITD_CONF" || true)
    awk '
        /^[[:space:]]*[A-Za-z_]+[[:space:]]*=/ {
            k=$1; val[k]=$0; if (!(k in seen)) { seen[k]=1; order[++n]=k }
            next
        }
        { other[++m]=$0 }
        END { for (i=1;i<=n;i++) print val[order[i]] }
    ' "$AUDITD_CONF" > "${AUDITD_CONF}.tmp" && mv "${AUDITD_CONF}.tmp" "$AUDITD_CONF"
    chmod 640 "$AUDITD_CONF"; chown root:root "$AUDITD_CONF"
    after=$(grep -cE '^[[:space:]]*[A-Za-z_]+[[:space:]]*=' "$AUDITD_CONF" || true)
    [[ "$before" != "$after" ]] && warn "auditd.conf: collapsed $((before-after)) duplicate key(s)."
    return 0
}

apply_auditd_conf() {
    local key="$1"
    local value="$2"
    # Anchor on the full key plus its '=' so that, e.g., "space_left" cannot
    # match "space_left_action".
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$AUDITD_CONF"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$AUDITD_CONF"
    else
        echo "${key} = ${value}" >> "$AUDITD_CONF"
    fi
    log "  auditd.conf: ${key} = ${value}"
}

dedupe_auditd_conf

# RAW rather than ENRICHED. ENRICHED appends translated AUID/UID/ARCH fields
# after a 0x1d separator on every record - measured at 14.5% of total audit
# volume on a reference endpoint. TA-linux_auditd resolves these at search
# time instead. Keep ENRICHED only if you rely on local ausearch forensics on
# hosts whose /etc/passwd may change before the logs are read.
apply_auditd_conf "log_format"               "RAW"
apply_auditd_conf "max_log_file"             "100"
apply_auditd_conf "num_logs"                "5"
apply_auditd_conf "max_log_file_action"     "ROTATE"
apply_auditd_conf "flush"                   "INCREMENTAL_ASYNC"
apply_auditd_conf "freq"                    "50"
apply_auditd_conf "priority_boost"          "4"
apply_auditd_conf "space_left"              "500"
apply_auditd_conf "space_left_action"       "SYSLOG"
apply_auditd_conf "admin_space_left"        "50"
apply_auditd_conf "admin_space_left_action" "SUSPEND"
apply_auditd_conf "disk_full_action"        "SUSPEND"
apply_auditd_conf "disk_error_action"       "SUSPEND"

ok "auditd.conf tuned."
service auditd restart 2>/dev/null || systemctl restart auditd || true

# auditd reloads rules asynchronously via augenrules; without waiting, the
# STEP 9 validation can run against an empty ruleset and report a spurious FAIL.
wait_for_audit_rules() {
    # Do NOT rely on polling the rule count after the restart.
    #
    # systemctl returns as soon as the main process is up, BEFORE the unit's
    # ExecStartPost=augenrules --load has started. Polling therefore samples
    # the PREVIOUS ruleset, which on a re-run has the same count as the new
    # one - so "the count looks stable" is satisfied by the stale ruleset, the
    # real reload lands moments later, and validation runs against a ruleset
    # that is mid-reload. That produced intermittent, misleading FAILs.
    #
    # Instead: wait for the unit to be genuinely active, then drive the load
    # ourselves and synchronously. augenrules is idempotent, so doing it again
    # after ExecStartPost is harmless, and when this returns the rules really
    # are in the kernel.
    local deadline=$((SECONDS + 30))

    # 1. Unit genuinely active.
    while (( SECONDS < deadline )); do
        systemctl is-active --quiet auditd && break
        sleep 1
    done
    if ! systemctl is-active --quiet auditd; then
        err "auditd did not become active within 30s. Check: journalctl -u auditd"
        return 0
    fi

    # 2. Let the unit's OWN ExecStartPost=augenrules --load run to completion.
    #    Do not start a second loader alongside it: augenrules reloads by
    #    issuing -D and re-adding, so two concurrent loaders interleave their
    #    deletes and adds and the final ruleset is nondeterministic.
    while (( SECONDS < deadline )); do
        pgrep -x augenrules >/dev/null 2>&1 || break
        sleep 1
    done
    sleep 1   # brief settle after the loader exits

    # 3. Only drive the load ourselves if the unit did not manage it.
    local count
    count=$(auditctl -l 2>/dev/null | grep -c '^-' || true)
    if (( count <= 10 )); then
        log "  Unit did not load rules — loading explicitly."
        augenrules --load >/dev/null 2>&1 || true
        count=$(auditctl -l 2>/dev/null | grep -c '^-' || true)
    fi

    if (( count > 10 )); then
        ok "auditd restarted — ${count} rules active."
    else
        warn "auditd is running but only ${count} rules loaded."
        warn "  Check: augenrules --load"
    fi

    # Rules in the file that the kernel rejected. Overwhelmingly these are
    # upstream rules referencing software absent from this host (VMware tools,
    # an EDR agent): auditctl validates -F exe= and -F dir= paths at load time
    # and skips the rule if the path does not exist. Reported, not fatal.
    local in_file skipped
    in_file=$(grep -c '^-[aw] ' /etc/audit/rules.d/audit.rules 2>/dev/null || echo 0)
    skipped=$(( in_file - count ))
    (( skipped > 0 )) && log "  ${skipped} rule(s) skipped — path not present on this host (expected)."
    return 0
}
wait_for_audit_rules

# ═══════════════════════════════════════════════════════════════════
# STEP 4: Verify rsyslog (/var/log/secure and /var/log/messages)
# ═══════════════════════════════════════════════════════════════════
section "STEP 4: Verify rsyslog — /var/log/secure and /var/log/messages"
log "RHEL/CentOS equivalent of Ubuntu's auth.log is /var/log/secure"
log "Maps to: T1110, T1078, T1548.003, T1136"

if ! systemctl is-active --quiet rsyslog; then
    warn "rsyslog not running — starting..."
    systemctl enable rsyslog
    systemctl start rsyslog
fi
ok "rsyslog is running."

# Check for /var/log/secure directive in rsyslog config
if grep -rq "secure" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
    ok "/var/log/secure is configured in rsyslog."
else
    warn "/var/log/secure not found in rsyslog config — adding..."
    echo 'authpriv.*    /var/log/secure' >> /etc/rsyslog.conf
    systemctl restart rsyslog
    ok "/var/log/secure directive added."
fi

# Check for /var/log/messages
if grep -rq "/var/log/messages" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
    ok "/var/log/messages is configured in rsyslog."
else
    warn "Adding /var/log/messages directive..."
    echo '*.info;mail.none;authpriv.none;cron.none    /var/log/messages' \
        >> /etc/rsyslog.conf
    systemctl restart rsyslog
    ok "/var/log/messages directive added."
fi

for f in /var/log/secure /var/log/messages /var/log/cron; do
    if [[ -f "$f" ]]; then
        ok "Log file exists: $f"
    else
        warn "Log file does not exist yet: $f (will be created on first event)"
    fi
done

SYSLOG_SERVICE="rsyslog"   # RHEL default; STEP 4 enforces it

# ═══════════════════════════════════════════════════════════════════
# STEP 4b: Curated syslog feed for Splunk (/var/log/splunk-syslog.log)
# ═══════════════════════════════════════════════════════════════════
section "STEP 4b: Curated syslog feed for Splunk"
log "Measured baseline: /var/log/messages averaged 36 MB/host/day — 68% one"
log "Java service's stdout, 13% containerd, 13% setroubleshoot (a prose copy"
log "of AVC denials already in audit.log). Security content was under 5%."

# The local files are NOT changed: admins keep full messages/syslog on disk.
# rsyslog writes a second, curated file and only that one is forwarded:
#   kept:    kern.*, cron.*, anything at warning or above, and the listed
#            security-relevant programs at every severity
#   dropped: auth/authpriv (already collected via the auth input),
#            setroubleshoot (duplicate of AVC), UFW per-packet lines
#            (perimeter firewall logs already cover them), and info-level
#            chatter from applications, containerd/dockerd and NetworkManager
CURATED_LOG="/var/log/splunk-syslog.log"
CURATED_CONF="/etc/rsyslog.d/48-splunk-curated.conf"

curate_syslog() {
    if [[ "$SYSLOG_SERVICE" != "rsyslog" ]]; then
        warn "$SYSLOG_SERVICE is not rsyslog — curated feed not configured."
        warn "  Point inputs.conf back at the full syslog file for this host."
        return 0
    fi

    local grp_opt=""
    getent group adm &>/dev/null && grp_opt=' fileGroup="adm"'

    cat > "$CURATED_CONF" <<EOF
# Managed by $(basename "$0") — curated feed for the Splunk forwarder.
# Local /var/log/messages and /var/log/syslog are untouched; only
# ${CURATED_LOG} is forwarded. Remove this file to revert.
if ( \$syslogfacility-text != "auth" and \$syslogfacility-text != "authpriv" )
   and not ( \$programname == ["setroubleshoot", "setroubleshootd"] )
   and not ( \$msg contains "[UFW " )
   and ( \$syslogfacility-text == ["kern", "cron"]
         or \$syslogseverity <= 4
         or \$programname == ["systemd", "systemd-logind", "sshd", "sshd-session",
                             "sudo", "su", "useradd", "userdel", "usermod",
                             "groupadd", "groupdel", "groupmod", "passwd",
                             "chpasswd", "chage", "gpasswd", "auditd", "audispd",
                             "augenrules", "rsyslogd", "polkitd", "dnf", "yum",
                             "rpm", "apt", "dpkg", "firewalld", "ufw", "sysmon",
                             "atd", "crond", "CROND", "CRON", "anacron", "kernel"] )
then {
    action(type="omfile" file="${CURATED_LOG}" template="RSYSLOG_FileFormat"
           fileCreateMode="0640"${grp_opt})
}
EOF
    chmod 644 "$CURATED_CONF"

    # Validate before restarting: a syntax error would stop ALL local logging.
    if ! rsyslogd -N1 >/dev/null 2>&1; then
        mv "$CURATED_CONF" "${CURATED_CONF}.invalid"
        err "rsyslog rejected the curated config — moved to ${CURATED_CONF}.invalid."
        err "  Run 'rsyslogd -N1' to see why. Local logging is unaffected."
        return 0
    fi
    systemctl restart rsyslog
    ok "Curated feed configured: ${CURATED_CONF} -> ${CURATED_LOG}"

    # Rotation. The UF follows rotations by CRC, so daily + delaycompress is safe.
    local owner="root"
    id syslog &>/dev/null && owner="syslog"
    cat > /etc/logrotate.d/splunk-syslog <<EOF
# Managed by $(basename "$0")
${CURATED_LOG} {
    daily
    rotate 7
    maxsize 200M
    missingok
    notifempty
    compress
    delaycompress
    create 0640 ${owner} adm
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF
    chmod 644 /etc/logrotate.d/splunk-syslog
    ok "Rotation configured: /etc/logrotate.d/splunk-syslog (daily, 7 kept)."

    # Self-test so the validation step has a file to check.
    logger -p daemon.warning -t splunk-curation "curated syslog feed self-test (safe to ignore)"
    sleep 1
}
curate_syslog

# ═══════════════════════════════════════════════════════════════════
# STEP 5: Verify SELinux is Enforcing
# ═══════════════════════════════════════════════════════════════════
section "STEP 5: Verify SELinux Status"
log "SELinux AVC denials appear in /var/log/audit/audit.log (type=AVC)"
log "Maps to: T1068 (Exploitation for Privilege Escalation)"

SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Unknown")
log "  Current SELinux mode: $SELINUX_STATUS"

if [[ "$SELINUX_STATUS" == "Enforcing" ]]; then
    ok "SELinux is Enforcing — AVC denials will appear in audit.log."
elif [[ "$SELINUX_STATUS" == "Permissive" ]]; then
    warn "SELinux is Permissive — AVC denials logged but not blocked."
    warn "Consider setting Enforcing: setenforce 1 (and edit /etc/selinux/config)"
else
    warn "SELinux is Disabled or status unknown."
    warn "AVC events will NOT appear. This reduces detection coverage significantly."
fi

# setroubleshoot is NOT installed by the budget profile. It re-writes every
# AVC denial as multi-line prose into /var/log/messages — measured at 13% of
# messages volume (~50 MB/day across 11 hosts) — while the AVC record itself
# is already collected from audit.log. The curated syslog feed excludes it,
# so an existing install costs no license; it is left in place for local use.
if rpm -q setroubleshoot-server &>/dev/null; then
    log "setroubleshoot-server present — kept locally, excluded from the Splunk feed."
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 6: journald Persistent Storage
# ═══════════════════════════════════════════════════════════════════
section "STEP 6: Configure journald Persistent Storage"

JOURNALD_CONF="/etc/systemd/journald.conf"

# Set a key in an INI-style [Section] file, idempotently.
#
# The previous implementation appended when it could not find a COMMENTED key,
# so the first run uncommented it and every later run appended a fresh copy -
# this host accumulated six SystemMaxUse=2G lines across five runs. Collapse any
# existing duplicates first, then set the live key in place.
set_ini_key() {
    local file="$1" key="$2" value="$3"
    [[ -f "$file" ]] || { warn "  $file not found — skipping ${key}."; return 0; }

    # Collapse duplicates of this key, keeping the last (the effective one).
    local n
    n=$(grep -cE "^[[:space:]]*${key}=" "$file" || true)
    if [[ "$n" -gt 1 ]]; then
        awk -v k="$key" '
            $0 ~ "^[[:space:]]*" k "=" { last = NR }
            { lines[NR] = $0 }
            END { for (i = 1; i <= NR; i++)
                      if (lines[i] !~ "^[[:space:]]*" k "=" || i == last) print lines[i] }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
        warn "  ${file##*/}: collapsed $((n-1)) duplicate ${key} line(s)."
    fi

    if grep -qE "^[[:space:]]*${key}=" "$file"; then
        sed -i -E "s|^[[:space:]]*${key}=.*|${key}=${value}|" "$file"
    elif grep -qE "^[[:space:]]*#[[:space:]]*${key}=" "$file"; then
        sed -i -E "0,/^[[:space:]]*#[[:space:]]*${key}=.*/s||${key}=${value}|" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
    log "  ${file##*/}: ${key}=${value}"
}

set_ini_key "$JOURNALD_CONF" "Storage"      "persistent"
set_ini_key "$JOURNALD_CONF" "SystemMaxUse" "2G"

mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
ok "journald restarted with persistent storage (/var/log/journal)."

# ═══════════════════════════════════════════════════════════════════
# STEP 7: File Permissions for Splunk UF
# ═══════════════════════════════════════════════════════════════════
section "STEP 7: Grant Splunk UF Read Access to Log Files"
log "Splunk UF (user: $SPLUNK_USER) needs read access to /var/log/audit/audit.log"

if id "$SPLUNK_USER" &>/dev/null; then
    # Add to 'adm' group if it exists, or 'root' group for log access
    if getent group adm &>/dev/null; then
        usermod -aG adm "$SPLUNK_USER" && \
            ok "  Added $SPLUNK_USER to 'adm' group" || \
            warn "  Could not add to adm group"
    fi

    # RHEL: log files owned by root:root — use ACLs
    if command -v setfacl &>/dev/null; then
        setfacl -m u:"$SPLUNK_USER":r /var/log/audit/ 2>/dev/null && \
        setfacl -m u:"$SPLUNK_USER":r /var/log/audit/audit.log 2>/dev/null && \
            ok "  ACL set: $SPLUNK_USER can read /var/log/audit/audit.log" || \
            warn "  setfacl failed — UF may need to run as root"
    else
        warn "  setfacl not available — install acl package: $PKG_MGR install -y acl"
        warn "  Splunk UF may need to run as root to read audit.log"
    fi

    # Ensure /var/log/secure and /var/log/messages are group-readable
    chmod o+r /var/log/secure /var/log/messages 2>/dev/null && \
        ok "  /var/log/secure and /var/log/messages made world-readable" || \
        warn "  Could not chmod log files (may not exist yet)"
else
    warn "Splunk user '$SPLUNK_USER' not found."
    warn "After installing the UF, run:"
    warn "  usermod -aG adm $SPLUNK_USER"
    warn "  setfacl -m u:${SPLUNK_USER}:r /var/log/audit/audit.log"
fi

# ── Stop the forwarder generating its own audit noise ─────────────
# 'splunk enable boot-start' writes a unit whose ExecStartPre does an
# unconditional "chown -R <user> $SPLUNK_HOME" on every start. That walks the
# whole install tree issuing an fchownat(2) per object, each of which auditd
# records and the forwarder then ships - measured at ~28% of total audit bytes
# across a restart-heavy window on a reference endpoint. The guard below still
# heals genuine ownership drift, but short-circuits on the first mismatch, so
# the normal case costs only a stat() walk, which is not audited.
SPLUNK_UNIT=""
for u in SplunkForwarder Splunkd splunk; do
    systemctl cat "${u}.service" &>/dev/null && { SPLUNK_UNIT="${u}.service"; break; }
done

if [[ -n "$SPLUNK_UNIT" ]] && systemctl cat "$SPLUNK_UNIT" 2>/dev/null | grep -q 'ExecStartPre=.*chown -R'; then
    SPLUNK_HOME_DIR=$(systemctl cat "$SPLUNK_UNIT" 2>/dev/null \
        | grep -m1 -oE 'chown -R [^ ]+ ([^"]+)' | awk '{print $4}')
    SPLUNK_HOME_DIR="${SPLUNK_HOME_DIR:-/opt/splunkforwarder}"
    DROPIN_DIR="/etc/systemd/system/${SPLUNK_UNIT}.d"
    mkdir -p "$DROPIN_DIR"
    {
        echo "# Managed by Enable-LinuxLogging-RHEL-CentOS.sh"
        echo "# Replaces the vendor unit's unconditional recursive chown, which"
        echo "# generates a large volume of perm_mod audit events on every start."
        echo "# Revert: rm this file && systemctl daemon-reload"
        echo ""
        echo "[Service]"
        echo "ExecStartPre="
        echo "ExecStartPre=-/bin/bash -c 'find ${SPLUNK_HOME_DIR} \\( ! -user ${SPLUNK_USER} -o ! -group ${SPLUNK_USER} \\) -print -quit | grep -q . && chown -R ${SPLUNK_USER}:${SPLUNK_USER} ${SPLUNK_HOME_DIR} || true'"
    } > "${DROPIN_DIR}/10-no-recursive-chown.conf"
    chmod 644 "${DROPIN_DIR}/10-no-recursive-chown.conf"
    systemctl daemon-reload
    ok "  ${SPLUNK_UNIT}: recursive chown replaced with a guarded check."
    log "  Restart the forwarder for this to take effect."
else
    log "  No Splunk unit with a recursive-chown ExecStartPre found — nothing to do."
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 8: Sysmon for Linux (Optional)
# ═══════════════════════════════════════════════════════════════════
section "STEP 8: Sysmon for Linux (Optional)"
log "Source: Microsoft MSTIC — MITRE ATT&CK coverage (T1105, T1071, T1059)"
log "Events appear in /var/log/messages on RHEL/CentOS"

if [[ "$SKIP_SYSMON" == "true" ]]; then
    log "Sysmon for Linux not installed (budget profile default; --with-sysmon to enable)."
    log "  Its process-create events would duplicate auditd process_creation."
else
    if command -v sysmon &>/dev/null; then
        ok "Sysmon for Linux already installed."
    else
        log "Adding Microsoft repository for RHEL/CentOS..."
        RHEL_VERSION="$OS_VERSION"

        if command -v curl &>/dev/null; then
            curl -fsSL \
                "https://packages.microsoft.com/config/rhel/${RHEL_VERSION}/packages-microsoft-prod.rpm" \
                -o /tmp/packages-microsoft-prod.rpm && \
            rpm -Uvh /tmp/packages-microsoft-prod.rpm 2>/dev/null || true
        elif command -v wget &>/dev/null; then
            wget -qO /tmp/packages-microsoft-prod.rpm \
                "https://packages.microsoft.com/config/rhel/${RHEL_VERSION}/packages-microsoft-prod.rpm" && \
            rpm -Uvh /tmp/packages-microsoft-prod.rpm 2>/dev/null || true
        else
            warn "curl/wget not available — cannot auto-install Sysmon."
        fi

        $PKG_MGR install -y sysinternals 2>/dev/null && \
            ok "Sysmon for Linux installed." || \
            warn "Sysmon install failed — install manually: https://github.com/Sysinternals/SysmonForLinux"
    fi

    if command -v sysmon &>/dev/null; then
        SYSMON_CONFIG="/etc/sysmon/sysmon-config.xml"
        mkdir -p /etc/sysmon
        if [[ ! -f "$SYSMON_CONFIG" ]]; then
            log "Deploying minimal Sysmon config..."
            cat > "$SYSMON_CONFIG" << 'EOF'
<Sysmon schemaversion="4.81">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
        <DestinationIp condition="is">::1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
EOF
            sysmon -accepteula -i "$SYSMON_CONFIG" 2>&1 | tee -a "$LOG_FILE" || \
                warn "Sysmon config failed — apply manually: sysmon -accepteula -i $SYSMON_CONFIG"
            ok "Sysmon deployed with minimal config."
            warn "Replace with MSTIC config: https://github.com/Azure/MSTIC-Sysmon"
        else
            ok "Sysmon config already exists at $SYSMON_CONFIG"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 9: Verify Package Manager Log
# ═══════════════════════════════════════════════════════════════════
section "STEP 9: Verify Package Manager Logging"
log "Maps to: T1072, T1195 — software installs/modifications"

# RHEL 8+ uses dnf; older uses yum
if [[ "$PKG_MGR" == "dnf" ]]; then
    if [[ -f /var/log/dnf.log ]]; then
        ok "/var/log/dnf.log exists."
    else
        warn "/var/log/dnf.log not yet created (created on first dnf operation)."
    fi
    if [[ -f /var/log/dnf.rpm.log ]]; then
        ok "/var/log/dnf.rpm.log exists."
    else
        warn "/var/log/dnf.rpm.log not yet created."
    fi
else
    if [[ -f /var/log/yum.log ]]; then
        ok "/var/log/yum.log exists."
    else
        warn "/var/log/yum.log not yet created."
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 10: Validation
# ═══════════════════════════════════════════════════════════════════
section "STEP 10: Validation"

check() {
    local label="$1"
    local cmd="$2"
    # pipefail must be OFF here. Checks of the form
    #     auditctl -l | grep -q PATTERN
    # exit the pipeline the instant grep matches, which SIGPIPEs the writer;
    # with pipefail the pipeline then reports the writer's 141, so the check
    # FAILS precisely when its pattern IS found - and only intermittently,
    # depending on whether the writer had already finished.
    local had_pipefail=0
    [[ -o pipefail ]] && had_pipefail=1
    set +o pipefail
    if eval "$cmd" &>/dev/null; then
        ok "  PASS: $label"
    else
        err "  FAIL: $label"
    fi
    (( had_pipefail )) && set -o pipefail
    return 0
}

check "auditd service running"              "systemctl is-active auditd"
check "auditd rules loaded (>10)"           "[[ \$(auditctl -l 2>/dev/null | wc -l) -gt 10 ]]"
check "log_format=RAW in auditd.conf"      "grep -q '^log_format = RAW' /etc/audit/auditd.conf"
check "auditd.conf has no duplicate keys"  "[[ \$(grep -oE '^[a-z_]+(?= *=)' -P /etc/audit/auditd.conf | sort | uniq -d | wc -l) -eq 0 ]]"
if [[ "$SKIP_VOLUME_TUNING" != "true" ]]; then
    check "perm_mod narrowed to key paths" "auditctl -l | grep -q 'dir=/etc.*perm_mod'"
    check "file_access rules disabled"     "[[ \$(auditctl -l | grep -c file_access) -eq 0 ]]"
    check "socket() noise rule disabled"   "[[ \$(auditctl -l | grep -c 'key=network_socket_created$') -eq 0 ]]"
    check "raw-socket rule KEPT (T1040)"   "auditctl -l | grep -q 'key=raw_network_socket_created'"
    check "delete narrowed to key paths"   "auditctl -l | grep -q 'dir=/var/log.*delete'"
    check "process_creation rule loaded"     "auditctl -l | grep -q 'execve.*process_creation'"
    check "PROCTITLE records excluded"       "auditctl -l | grep -q 'msgtype=PROCTITLE'"
    check "/var/lib/docker data watch gone"  "[[ \$(auditctl -l | grep -c '/var/lib/docker') -eq 0 ]]"
    check "exec from /tmp still logged"      "auditctl -l | grep -q 'dir=/tmp .*process_creation'"
    check "unauthedfileaccess_system cut"    "[[ \$(auditctl -l | grep -c 'key=unauthedfileaccess_system') -eq 0 ]]"
    if [[ "$FULL_EXEC" != "true" ]]; then
        check "daemon execs narrowed (policy 1)" "auditctl -l | grep -qE 'never,exit.*execve.*auid=(-1|unset|4294967295)'"
        check "shell exec exception present"     "auditctl -l | grep -qE 'exe=/(usr/)?bin/(bash|dash) .*process_creation'"
    fi
    if [[ "$FULL_CONNECT" != "true" ]]; then
        check "connect scoped (policy 2)"        "[[ \$(auditctl -l | grep 'key=network_connect_4' | grep -vcE 'auid!=|exe=') -eq 0 ]]"
    fi
fi
check "audit.log exists"                   "[[ -f /var/log/audit/audit.log ]]"
check "curated rsyslog config valid"       "[[ -f $CURATED_CONF ]] && rsyslogd -N1"
check "curated feed file exists"           "[[ -f $CURATED_LOG ]]"
check "curated feed received self-test"    "grep -q 'curated syslog feed self-test' $CURATED_LOG"
check "curated feed rotation configured"   "[[ -f /etc/logrotate.d/splunk-syslog ]]"
check "rsyslog running"                    "systemctl is-active rsyslog"
check "/var/log/secure exists"             "[[ -f /var/log/secure ]]"
check "/var/log/messages exists"           "[[ -f /var/log/messages ]]"
check "/var/log/cron exists"               "[[ -f /var/log/cron ]]"
check "journald persistent storage"        "grep -q 'Storage=persistent' /etc/systemd/journald.conf"
check "journald.conf has no duplicate keys" "[[ \$(grep -oE '^[A-Za-z]+(?==)' -P /etc/systemd/journald.conf | sort | uniq -d | wc -l) -eq 0 ]]"
check "acl installed (setfacl available)"   "command -v setfacl"
check "SELinux not Disabled"               "[[ \$(getenforce 2>/dev/null) != 'Disabled' ]]"
if [[ "$SKIP_SYSMON" != "true" ]]; then
    check "sysmon installed"               "command -v sysmon"
fi

# ═══════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}$(printf '%.0s=' {1..70})${NC}"
echo -e "${GREEN}  COMPLETED — RHEL/CentOS Logging Prerequisites${NC}"
echo -e "${GREEN}$(printf '%.0s=' {1..70})${NC}"
echo ""
log "Full log saved to: $LOG_FILE"
echo ""
echo -e "${YELLOW}  Next steps:${NC}"
echo -e "${YELLOW}  1. Deploy the budget RHEL/CentOS inputs.conf to: \$SPLUNK_HOME/etc/system/local/${NC}"
echo -e "${YELLOW}  2. Deploy outputs.conf to:                       \$SPLUNK_HOME/etc/system/local/${NC}"
echo -e "${YELLOW}  3. Restart Splunk UF:                            \$SPLUNK_HOME/bin/splunk restart${NC}"
echo -e "${YELLOW}  4. If UF not running as root, ensure $SPLUNK_USER is in adm group${NC}"
echo -e "${YELLOW}  5. Forwarded paths: audit.log, secure, splunk-syslog.log, dnf logs${NC}"
echo -e "${YELLOW}     (messages and cron are no longer forwarded — curated feed replaces them)${NC}"
echo -e "${YELLOW}  6. After 24h, check this host's MB/day in license_usage.log (target <62 MB)${NC}"
echo ""
