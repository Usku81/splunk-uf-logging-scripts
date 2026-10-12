#!/usr/bin/env bash
# =============================================================================
# Enable-LinuxLogging-Ubuntu.sh
#
# PURPOSE  : Enable prerequisite logging for Splunk UF collection — BUDGET
#            PROFILE (~62 MB/host/day, all Linux sources) — on
#            Ubuntu 20.04 / 22.04 / 24.04 LTS.
#
# APPLIES  : - auditd installation + Neo23x0 ruleset (pinned, with a vendored
#              fallback so every host in a fleet gets identical rules)
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
#            - rsyslog verification + auth.log / syslog
#            - journald persistent storage
#            - Sysmon for Linux (opt-in: --with-sysmon)
#            - Log file permission hardening for Splunk UF read access
#
# SOURCES  : Neo23x0/auditd, MITRE ATT&CK M1047, Red Hat Security Guide,
#            ACSC, Splunk TA-linux_auditd docs
#
# USAGE    :
#   sudo bash Enable-LinuxLogging-Ubuntu.sh [OPTIONS]
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
# REQUIREMENTS : Ubuntu 20.04, 22.04 or 24.04 LTS, run as root / sudo
# =============================================================================

set -euo pipefail

# ── Defaults ───────────────────────────────────────────────────────
SKIP_SYSMON=true            # budget profile: Sysmon is opt-in
FULL_EXEC=false
FULL_CONNECT=false
SKIP_AUDITD_RULES=false
SKIP_VOLUME_TUNING=false
SPLUNK_USER="splunkfwd"
LOG_FILE="/var/log/splunk-prereq-ubuntu-$(date +%Y%m%d_%H%M%S).log"
# Pinned to a commit, not master. Across a fleet rolled out over days or weeks,
# tracking master means hosts silently end up on different rulesets depending on
# when they happened to run, and a detection gap becomes impossible to reason
# about. Bump this deliberately, re-test, then redeploy.
NEO23X0_RULES_REF="6111069472c26c4120002933b67cef9855dfbad5"   # 2026-05-04
NEO23X0_RULES_URL="https://raw.githubusercontent.com/Neo23x0/auditd/${NEO23X0_RULES_REF}/audit.rules"
# OPTIONAL vendored copy, used when the host has no outbound internet access
# (common for hardened/air-gapped servers) or when GitHub is unreachable.
# Not shipped in the repository by default - to use it, fetch the pinned
# ruleset once and place it next to this script as 'audit.rules.neo23x0':
#
#   curl -fsSL https://raw.githubusercontent.com/Neo23x0/auditd/\
#${NEO23X0_RULES_REF}/audit.rules -o audit.rules.neo23x0
#
# With it present, every host in the fleet is guaranteed the same rules even
# without network access. Without it, a host that cannot reach GitHub keeps
# whatever ruleset it already has and the script says so.
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

# ── OS check ───────────────────────────────────────────────────────
if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    warn "This script targets Ubuntu. Detected OS may differ — proceeding anyway."
fi

echo ""
echo -e "${BOLD}  Splunk UF Prerequisite — Ubuntu 20.04 / 22.04 / 24.04 LTS${NC}"
echo -e "  Log file: ${LOG_FILE}"
echo ""

# ═══════════════════════════════════════════════════════════════════
# STEP 1: Install auditd
# ═══════════════════════════════════════════════════════════════════
section "STEP 1: Install and Enable auditd"
log "Source: MITRE ATT&CK M1047, Neo23x0/auditd, ACSC"

# dpkg -l succeeds for a package that is merely *known* to dpkg, including one
# removed but not purged ('rc' state). Check the actual install status instead.
pkg_installed() {
    dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -q '^installed$'
}

# 'acl' provides setfacl, used in STEP 7 to grant the UF read access to
# audit.log. It is absent from Ubuntu Server minimal and cloud images, and
# without it the UF silently cannot read the primary security log source.
# Checked independently of auditd: on a host where auditd is already present,
# acl may still be missing.
APT_UPDATED=false
NEEDED=()
pkg_installed auditd            || NEEDED+=(auditd audispd-plugins)
pkg_installed acl               || NEEDED+=(acl)

if [[ ${#NEEDED[@]} -gt 0 ]]; then
    log "Installing: ${NEEDED[*]}"
    apt-get update -qq && APT_UPDATED=true
    apt-get install -y "${NEEDED[@]}"
    ok "Installed: ${NEEDED[*]}"
else
    ok "auditd and acl already installed."
fi

if ! command -v setfacl &>/dev/null; then
    warn "setfacl still unavailable — STEP 7 will fall back to group permissions."
fi

systemctl enable auditd
systemctl start auditd
ok "auditd enabled and started."

# ═══════════════════════════════════════════════════════════════════
# STEP 2: Deploy Neo23x0 Auditd Rules
# ═══════════════════════════════════════════════════════════════════
section "STEP 2: Deploy auditd Rules (Neo23x0 Best-Practice Baseline)"
log "Source: https://github.com/Neo23x0/auditd"
log "Covers: T1059, T1053, T1136, T1098, T1548, T1547, T1070, T1105, T1110"

if [[ "$SKIP_AUDITD_RULES" == "true" ]]; then
    warn "Skipping auditd rules download (--skip-auditd-rules)."
else
    # Backup existing rules
    if [[ -f /etc/audit/rules.d/audit.rules ]]; then
        cp /etc/audit/rules.d/audit.rules \
           "/etc/audit/rules.d/audit.rules.bak.$(date +%Y%m%d_%H%M%S)"
        warn "Existing rules backed up."
    fi

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
log "Loading auditd rules..."
augenrules --load 2>&1 | tee -a "$LOG_FILE" || true
RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l || echo 0)
if [[ "$RULE_COUNT" -gt 10 ]]; then
    ok "Auditd rules loaded. Active rule count: $RULE_COUNT"
else
    warn "Rule count low ($RULE_COUNT) — rules may not have loaded correctly."
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 3: Tune auditd.conf
# ═══════════════════════════════════════════════════════════════════
section "STEP 3: Tune /etc/audit/auditd.conf"
log "Setting log_format=RAW, increasing log size, configuring rotation"

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
apply_auditd_conf "log_format"              "RAW"
apply_auditd_conf "max_log_file"            "100"
apply_auditd_conf "num_logs"               "5"
apply_auditd_conf "max_log_file_action"    "ROTATE"
apply_auditd_conf "flush"                  "INCREMENTAL_ASYNC"
apply_auditd_conf "freq"                   "50"
apply_auditd_conf "priority_boost"         "4"
apply_auditd_conf "space_left"             "500"
apply_auditd_conf "space_left_action"      "SYSLOG"
apply_auditd_conf "admin_space_left"       "50"
apply_auditd_conf "admin_space_left_action" "SUSPEND"
apply_auditd_conf "disk_full_action"       "SUSPEND"
apply_auditd_conf "disk_error_action"      "SUSPEND"

ok "auditd.conf tuned."

# Restart auditd to apply config.
#
# auditd.service reloads the ruleset from an ExecStartPost=augenrules --load,
# which completes asynchronously after systemctl returns. Without waiting, the
# STEP 9 validation can run against an empty ruleset and report a spurious
# FAIL on a host that is in fact configured correctly.
systemctl restart auditd

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
# STEP 4: Verify rsyslog (or equivalent) and Auth Logging
# ═══════════════════════════════════════════════════════════════════
section "STEP 4: Verify Syslog Daemon and Auth Logging (/var/log/auth.log)"
log "Source: Ubuntu default rsyslog config — auth,authpriv.* → /var/log/auth.log"

# Detect an already-installed syslog daemon (rsyslog or a known equivalent).
# If none is present, fall back to installing rsyslog.
SYSLOG_SERVICE=""
for candidate in rsyslog syslog-ng inetutils-syslogd; do
    if dpkg -l "$candidate" 2>/dev/null | grep -q '^ii'; then
        SYSLOG_SERVICE="$candidate"
        ok "Detected installed syslog daemon: $candidate"
        break
    fi
done

if [[ -z "$SYSLOG_SERVICE" ]]; then
    warn "No syslog daemon found (checked: rsyslog, syslog-ng, inetutils-syslogd)."
    log "Installing rsyslog..."
    apt-get update -qq
    apt-get install -y rsyslog
    SYSLOG_SERVICE="rsyslog"
    ok "rsyslog installed."
fi

if ! systemctl is-active --quiet "$SYSLOG_SERVICE"; then
    warn "$SYSLOG_SERVICE not running — starting..."
    systemctl enable "$SYSLOG_SERVICE"
    systemctl start "$SYSLOG_SERVICE"
fi
ok "$SYSLOG_SERVICE is running."

# The auth.log directive check/insert below is rsyslog-specific syntax.
if [[ "$SYSLOG_SERVICE" == "rsyslog" ]]; then
    # Ensure auth.log facility is configured
    RSYSLOG_DEFAULT="/etc/rsyslog.d/50-default.conf"
    if grep -q "auth.log" "$RSYSLOG_DEFAULT" 2>/dev/null; then
        ok "/var/log/auth.log configured in rsyslog."
    else
        warn "auth.log not explicitly found in $RSYSLOG_DEFAULT — checking /etc/rsyslog.conf"
        if grep -q "auth.log" /etc/rsyslog.conf 2>/dev/null; then
            ok "/var/log/auth.log configured in /etc/rsyslog.conf."
        else
            warn "Adding auth.log to rsyslog config..."
            echo 'auth,authpriv.*    /var/log/auth.log' >> "$RSYSLOG_DEFAULT"
            systemctl restart rsyslog
            ok "auth.log directive added and rsyslog restarted."
        fi
    fi
else
    warn "$SYSLOG_SERVICE detected instead of rsyslog — verify auth.log routing manually (config syntax differs)."
fi

# Ensure auth.log and syslog exist
for f in /var/log/auth.log /var/log/syslog /var/log/kern.log; do
    if [[ -f "$f" ]]; then
        ok "Log file exists: $f"
    else
        warn "Log file does not exist yet: $f (will be created on next event)"
    fi
done

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
# STEP 5: journald Persistent Storage
# ═══════════════════════════════════════════════════════════════════
section "STEP 5: Configure journald Persistent Storage"
log "Prevents log loss on reboot. Source: systemd documentation."

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

systemctl restart systemd-journald
ok "journald restarted with persistent storage."

# Create journal directory
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
ok "Journal persistence directory: /var/log/journal"

# ═══════════════════════════════════════════════════════════════════
# STEP 6: Cron Logging
# ═══════════════════════════════════════════════════════════════════
section "STEP 6: Verify Cron Logging Reaches syslog"
log "Maps to: T1053.003 (Scheduled Task/Job: Cron)"

# Earlier revisions created /etc/rsyslog.d/51-cron.conf to route cron into a
# dedicated /var/log/cron.log. That was a mistake on Ubuntu.
#
# Ubuntu's default rule is:
#     *.*;auth,authpriv.none      -/var/log/syslog
# The cron facility is inside that *.*, so cron already reaches syslog. Adding
# cron.log writes every cron event to disk a second time, and collecting both
# files indexes it a second time. Measured on a reference host: 17 of 17
# cron.log lines were already present verbatim in syslog.
#
# Ubuntu ships the cron.log directive commented out for exactly this reason.
# So: verify the routing, do not duplicate it. inputs.conf has the cron.log
# monitor disabled to match.
if [[ "$SYSLOG_SERVICE" == "rsyslog" ]]; then
    if grep -qrE '^[[:space:]]*\*\.\*' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
        ok "cron reaches /var/log/syslog via the catch-all rule — already collected."
    elif grep -qrE '^[[:space:]]*[^#[:space:]].*cron\.\*' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
        ok "An explicit cron routing rule is present."
    else
        warn "No rule appears to route cron anywhere. Cron events may be lost."
        warn "  Add to /etc/rsyslog.d/51-cron.conf:  cron.*  -/var/log/cron.log"
        warn "  and set disabled = false on the cron.log stanza in inputs.conf."
    fi

    # Clean up the duplicate created by earlier runs of this script.
    if [[ -f /etc/rsyslog.d/51-cron.conf ]]; then
        mv /etc/rsyslog.d/51-cron.conf /etc/rsyslog.d/51-cron.conf.disabled
        systemctl restart rsyslog
        warn "Removed /etc/rsyslog.d/51-cron.conf (duplicated cron into syslog)."
        warn "  Kept as 51-cron.conf.disabled. /var/log/cron.log will stop growing;"
        warn "  cron events continue to arrive via syslog."
    fi
else
    warn "$SYSLOG_SERVICE detected instead of rsyslog — verify cron routing manually."
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 7: Set File Permissions for Splunk UF
# ═══════════════════════════════════════════════════════════════════
section "STEP 7: Grant Splunk UF Read Access to Log Files"
log "Splunk UF (user: $SPLUNK_USER) needs read access to /var/log/audit/audit.log"

if id "$SPLUNK_USER" &>/dev/null; then
    # Add Splunk user to adm group (reads most /var/log/ files)
    usermod -aG adm "$SPLUNK_USER" 2>/dev/null && \
        ok "  Added $SPLUNK_USER to 'adm' group (access to /var/log/)" || \
        warn "  Could not add $SPLUNK_USER to adm group"

    # Grant access to audit log (requires special handling)
    if [[ -f /var/log/audit/audit.log ]]; then
        setfacl -m u:"$SPLUNK_USER":r /var/log/audit/ 2>/dev/null && \
        setfacl -m u:"$SPLUNK_USER":r /var/log/audit/audit.log 2>/dev/null && \
            ok "  ACL set: $SPLUNK_USER can read /var/log/audit/audit.log" || \
            warn "  setfacl failed — Splunk UF may need to run as root to read audit.log"
    fi

    # Make log group readable
    chmod g+r /var/log/auth.log /var/log/syslog /var/log/kern.log 2>/dev/null || true
    ok "  Log file permissions updated."
else
    warn "Splunk user '$SPLUNK_USER' not found — run this step after installing the UF."
    warn "Ensure UF runs as root, or use: usermod -aG adm <splunk_user>"
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
        echo "# Managed by Enable-LinuxLogging-Ubuntu.sh"
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

if [[ "$SKIP_SYSMON" == "true" ]]; then
    log "Sysmon for Linux not installed (budget profile default; --with-sysmon to enable)."
    log "  Its process-create events would duplicate auditd process_creation."
else
    if command -v sysmon &>/dev/null; then
        ok "Sysmon for Linux already installed: $(sysmon --version 2>/dev/null || echo 'version unknown')"
    else
        log "Adding Microsoft package repository..."
        # lsb_release comes from the 'lsb-release' package, which is absent on
        # Ubuntu Server minimal and cloud images. Falling back to a hardcoded
        # 22.04 there would silently add the wrong repo on a 24.04 host, so read
        # /etc/os-release (always present) and only fall back as a last resort.
        UBUNTU_VERSION=$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}")
        [[ -z "$UBUNTU_VERSION" ]] && UBUNTU_VERSION=$(lsb_release -rs 2>/dev/null || echo "22.04")
        log "  Detected Ubuntu ${UBUNTU_VERSION} for Microsoft repo selection."

        if command -v curl &>/dev/null; then
            curl -fsSL "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb" \
                -o /tmp/packages-microsoft-prod.deb && \
            dpkg -i /tmp/packages-microsoft-prod.deb && \
            apt-get update -qq && \
            apt-get install -y sysinternals && \
            ok "Sysmon for Linux installed." || \
            warn "Sysmon installation failed — install manually from: https://github.com/Sysinternals/SysmonForLinux"
        else
            warn "curl not found — cannot auto-install Sysmon."
            warn "Install manually: https://github.com/Sysinternals/SysmonForLinux"
        fi
    fi

    # If sysmon is now available, deploy a basic config
    if command -v sysmon &>/dev/null; then
        SYSMON_CONFIG="/etc/sysmon/sysmon-config.xml"
        mkdir -p /etc/sysmon
        if [[ ! -f "$SYSMON_CONFIG" ]]; then
            log "Deploying minimal Sysmon config..."
            cat > "$SYSMON_CONFIG" << 'EOF'
<Sysmon schemaversion="4.81">
  <EventFiltering>
    <!-- Log all process creations (EID 1) -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- Log all network connections (EID 3) — exclude loopback -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
        <DestinationIp condition="is">::1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
    <!-- Log all file creates (EID 11) -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
EOF
            sysmon -accepteula -i "$SYSMON_CONFIG" 2>&1 | tee -a "$LOG_FILE" || \
                warn "Sysmon config deployment failed — apply manually."
            ok "Sysmon deployed with minimal config: $SYSMON_CONFIG"
            warn "VOLUME WARNING — this starter config is deliberately unfiltered:"
            warn "  * ProcessCreate (EID 1) duplicates auditd's process_creation key."
            warn "    You are now collecting every process execution TWICE."
            warn "  * FileCreate (EID 11) has an empty exclude list, so it logs every"
            warn "    file creation on the host. On a busy server this will dwarf every"
            warn "    other source combined."
            warn "  Before leaving this in place, either drop the auditd execve rules or"
            warn "  drop Sysmon EID 1, and add real FileCreate exclusions."
            warn "  Measure before deciding — see the byte-attribution command in the"
            warn "  byte-attribution recipe in the repository README."
            warn "  Replace with the MSTIC config for filtered ATT&CK coverage:"
            warn "  https://github.com/Azure/MSTIC-Sysmon"
        else
            ok "Sysmon config already exists at $SYSMON_CONFIG"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# STEP 9: Validation
# ═══════════════════════════════════════════════════════════════════
section "STEP 9: Validation"

check() {
    local label="$1"
    local cmd="$2"
    # pipefail must be OFF here. Several checks are of the form
    #     auditctl -l | grep -q PATTERN
    # and grep -q exits the instant it matches, which SIGPIPEs the writer.
    # With pipefail the pipeline then reports the writer's 141, so a check
    # FAILS precisely when its pattern IS found - and only sometimes, since
    # it depends on whether the writer had already finished. Measured on this
    # host: 14 of 15 spurious failures with pipefail, 0 of 15 without.
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

check "auditd service running"               "systemctl is-active auditd"
check "auditd rules loaded (>10)"            "[[ \$(auditctl -l 2>/dev/null | wc -l) -gt 10 ]]"
check "log_format=RAW in auditd.conf"        "grep -q '^log_format = RAW' /etc/audit/auditd.conf"
check "auditd.conf has no duplicate keys"    "[[ \$(grep -oE '^[a-z_]+(?= *=)' -P /etc/audit/auditd.conf | sort | uniq -d | wc -l) -eq 0 ]]"
if [[ "$SKIP_VOLUME_TUNING" != "true" ]]; then
    check "perm_mod narrowed to key paths"   "auditctl -l | grep -q 'dir=/etc.*perm_mod'"
    check "file_access rules disabled"       "[[ \$(auditctl -l | grep -c file_access) -eq 0 ]]"
    check "socket() noise rule disabled"     "[[ \$(auditctl -l | grep -c 'key=network_socket_created$') -eq 0 ]]"
    check "raw-socket rule KEPT (T1040)"     "auditctl -l | grep -q 'key=raw_network_socket_created'"
    check "delete narrowed to key paths"     "auditctl -l | grep -q 'dir=/var/log.*delete'"
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
check "audit.log exists"                     "[[ -f /var/log/audit/audit.log ]]"
check "curated rsyslog config valid"       "[[ -f $CURATED_CONF ]] && rsyslogd -N1"
check "curated feed file exists"           "[[ -f $CURATED_LOG ]]"
check "curated feed received self-test"    "grep -q 'curated syslog feed self-test' $CURATED_LOG"
check "curated feed rotation configured"   "[[ -f /etc/logrotate.d/splunk-syslog ]]"
check "syslog daemon ($SYSLOG_SERVICE) running" "systemctl is-active $SYSLOG_SERVICE"
check "auth.log exists"                      "[[ -f /var/log/auth.log ]]"
check "syslog exists"                        "[[ -f /var/log/syslog ]]"
check "kern.log exists"                      "[[ -f /var/log/kern.log ]]"
check "journald persistent storage"          "grep -q '^Storage=persistent' /etc/systemd/journald.conf"
check "journald.conf has no duplicate keys"  "[[ \$(grep -oE '^[A-Za-z]+(?==)' -P /etc/systemd/journald.conf | sort | uniq -d | wc -l) -eq 0 ]]"
check "acl installed (setfacl available)"    "command -v setfacl"
check "cron reaches syslog (not duplicated)" "grep -qrE '^[[:space:]]*\*\.\*' /etc/rsyslog.conf /etc/rsyslog.d/"
check "no duplicate cron.log routing"        "[[ ! -f /etc/rsyslog.d/51-cron.conf ]]"
check "journal directory exists"             "[[ -d /var/log/journal ]]"
if [[ "$SKIP_SYSMON" != "true" ]]; then
    check "sysmon installed"                 "command -v sysmon"
fi

# ═══════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}$(printf '%.0s=' {1..70})${NC}"
echo -e "${GREEN}  COMPLETED — Ubuntu Logging Prerequisites${NC}"
echo -e "${GREEN}$(printf '%.0s=' {1..70})${NC}"
echo ""
log "Full log saved to: $LOG_FILE"
echo ""
echo -e "${YELLOW}  Next steps:${NC}"
echo -e "${YELLOW}  1. Deploy the budget Ubuntu inputs.conf to: \$SPLUNK_HOME/etc/system/local/${NC}"
echo -e "${YELLOW}     (it forwards /var/log/splunk-syslog.log instead of /var/log/syslog)${NC}"
echo -e "${YELLOW}  2. Deploy outputs.conf to:                  \$SPLUNK_HOME/etc/system/local/${NC}"
echo -e "${YELLOW}  3. Restart Splunk UF:                       \$SPLUNK_HOME/bin/splunk restart${NC}"
echo -e "${YELLOW}  4. If UF is not running as root, ensure $SPLUNK_USER is in adm group${NC}"
echo -e "${YELLOW}  5. After 24h, check this host's MB/day in license_usage.log (target <62 MB)${NC}"
echo ""
