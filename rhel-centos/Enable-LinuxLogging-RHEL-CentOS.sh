#!/usr/bin/env bash
# =============================================================================
# Enable-LinuxLogging-RHEL-CentOS.sh
#
# PURPOSE  : Enable all prerequisite logging for Splunk UF collection on
#            RHEL 8/9 and CentOS 8 Stream.
#
# APPLIES  : - auditd enablement + Neo23x0 ruleset (pinned, with an optional
#              vendored fallback so every host in a fleet gets identical rules)
#            - auditd.conf tuning (RAW format, dedupe, log rotation)
#            - audit volume curation: cuts file_access, file_creation and
#              file_modification (EACCES/EPERM noise) and network_socket_created;
#              narrows perm_mod and delete to security-relevant paths; keeps
#              process_creation system-wide and deliberately un-scoped by auid
#            - rsyslog verification (/var/log/secure, /var/log/messages)
#            - SELinux verification (Enforcing mode)
#            - journald persistent storage
#            - Sysmon for Linux (optional)
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
#     --skip-sysmon          Skip Sysmon for Linux installation
#     --skip-auditd-rules    Skip downloading Neo23x0 rules (use existing)
#     --skip-volume-tuning   Keep the stock Neo23x0 ruleset verbatim (do not
#                            narrow perm_mod / disable file_access)
#     --splunk-user USER     Splunk UF run-as user (default: splunk)
#     --help                 Show this help
#
# REQUIREMENTS : RHEL 8/9 or CentOS 8 Stream, run as root / sudo
# =============================================================================

set -euo pipefail

# ── Defaults ───────────────────────────────────────────────────────
SKIP_SYSMON=false
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
        --skip-sysmon)       SKIP_SYSMON=true        ;;
        --skip-auditd-rules) SKIP_AUDITD_RULES=true  ;;
        --skip-volume-tuning) SKIP_VOLUME_TUNING=true ;;
        --splunk-user)       SPLUNK_USER="$2"; shift  ;;
        --help)
            grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,1\}//'
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

# ── Volume tuning ─────────────────────────────────────────────────
# Runs after the download, because the download overwrites any edits.
#
# Rationale, from byte-attribution on a reference endpoint (see README,
# "Measuring audit volume"): the stock Neo23x0 ruleset applies perm_mod
# system-wide, so it fires on every package install and every recursive
# chown, and file_access records failed opens (EACCES/EPERM) by ordinary
# users, which are overwhelmingly benign. Both are high-volume, low-yield.
tune_audit_volume() {
    local RULES="${1:-/etc/audit/rules.d/audit.rules}"
    local BEG="## >>> BEGIN volume-tuning (managed) >>>"
    local END="## <<< END volume-tuning (managed) <<<"

    if [[ ! -f "$RULES" ]]; then
        warn "No ruleset at $RULES — skipping volume tuning."
        return 0
    fi

    # Idempotent: drop any previous managed block, re-enable prior disables.
    # Both markers must be stripped, or a re-run without a fresh download
    # (--skip-auditd-rules) would prefix already-prefixed lines.
    sed -i "/^${BEG}\$/,/^${END}\$/d" "$RULES"
    sed -i 's|^## \[volume-tuning disabled\] ||' "$RULES"
    sed -i 's|^## \[volume-tuning absent-path\] ||' "$RULES"

    # ── 1. Rule families disabled outright ────────────────────────
    #
    # Each of these was measured against server-like activity (desktop and
    # interactive-session noise excluded) before being cut. Percentages below
    # are that measurement's share of total server-like audit bytes.
    #
    #   file_access         open() -> EACCES/EPERM. Records failed opens by
    #                       unprivileged users. Overwhelmingly benign, and it
    #                       spikes hard whenever a service lacks a permission.
    #   file_creation       Same EACCES/EPERM pattern, for create-type calls.
    #   file_modification   Same EACCES/EPERM pattern, for rename/truncate/chmod.
    #   network_socket_created
    #                       socket(AF_INET/AF_INET6). Fires on every outbound
    #                       DNS lookup and HTTP client call. A socket with no
    #                       connect() carries no detection signal on its own,
    #                       and connect() is separately covered for both IPv4
    #                       (a2=16) and IPv6 (a2=28), which is where the actual
    #                       C2 / lateral-movement evidence lives.
    local CUT_KEYS=(file_access file_creation file_modification network_socket_created)

    local k n_off=0
    for k in "${CUT_KEYS[@]}"; do
        sed -i -E "s|^(-a .*-k ${k})[[:space:]]*\$|## [volume-tuning disabled] \1|" "$RULES"
    done
    # perm_mod and delete are replaced rather than removed (see below).
    sed -i -E 's|^(-a .*-k (perm_mod\|delete))[[:space:]]*$|## [volume-tuning disabled] \1|' "$RULES"
    n_off=$(grep -c '^## \[volume-tuning disabled\]' "$RULES" || true)

    # ── 2. Rebuild the two "right idea, wrong scope" families ─────
    local PERM="chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown"
    PERM="${PERM},setxattr,lsetxattr,fsetxattr"
    PERM="${PERM},removexattr,lremovexattr,fremovexattr"
    local DEL="rmdir,unlink,unlinkat,rename,renameat,renameat2"

    # Permission changes matter where they grant privilege or backdoor a binary.
    # /opt is deliberately absent: agent software recursively chowns itself.
    local PERM_DIRS=(/etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /boot)
    # Deletion matters as anti-forensics (T1070) and persistence tampering,
    # not as a record of users tidying up their own files.
    local DEL_DIRS=(/etc /bin /sbin /usr/bin /usr/sbin /boot /var/log /var/spool/cron)

    local BLK N_ADD=0 d a
    BLK=$(mktemp)
    {
        echo "$BEG"
        echo "## Curated from the pinned Neo23x0 baseline. Three kinds of change:"
        echo "##   cut      - low signal per byte, removed entirely"
        echo "##   narrowed - right intent, wrong scope; rebuilt against the"
        echo "##              paths where the event actually means something"
        echo "##   kept     - everything else, including process_creation"
        echo "##"
        echo "## process_creation (execve) is deliberately NOT scoped by auid."
        echo "## Restricting it to auid>=1000 is the common advice and it is a"
        echo "## trap: a process spawned by a network service has auid=unset, so"
        echo "## a web shell running as www-data would execute completely"
        echo "## unlogged. It is the largest single source of volume here and"
        echo "## also the most valuable - pay for it, and cut elsewhere."
        echo "##"
        echo "## SITE SUPPRESSIONS go immediately below, before the always,exit"
        echo "## rules - auditd is first-match, so anything placed after them is"
        echo "## never reached. Suppressing by -F exe= is a real detection gap:"
        echo "## whatever an attacker can invoke as that path becomes invisible."
        echo "## Prefer fixing the noisy process. To find which exe is actually"
        echo "## costing you, attribute whole audit events to their executable -"
        echo "## the byte-attribution recipe is in the repository README:"
        echo "##   https://github.com/Usku81/splunk-uf-logging-scripts"
        echo "## Then suppress only the confirmed-benign one, e.g.:"
        echo "##   -a never,exit -F arch=b64 -S all -F exe=/usr/bin/some-agent"
        echo ""
        for d in "${PERM_DIRS[@]}"; do
            [[ -d "$d" ]] || continue          # auditctl rejects a missing dir=
            for a in b64 b32; do
                echo "-a always,exit -F arch=${a} -S ${PERM} -F dir=${d} -F auid>=1000 -F auid!=unset -k perm_mod"
                N_ADD=$((N_ADD + 1))
            done
        done
        echo ""
        for d in "${DEL_DIRS[@]}"; do
            [[ -d "$d" ]] || continue
            for a in b64 b32; do
                echo "-a always,exit -F arch=${a} -S ${DEL} -F dir=${d} -F auid>=1000 -F auid!=unset -k delete"
                N_ADD=$((N_ADD + 1))
            done
        done
        echo ""
        echo "$END"
    } > "$BLK"

    if ! grep -q '^-a always,exit' "$RULES"; then
        warn "No 'always,exit' rule found — skipping volume tuning."
        rm -f "$BLK"; return 0
    fi
    awk -v blk="$BLK" '
        !spliced && /^-a always,exit/ {
            while ((getline l < blk) > 0) print l
            close(blk); spliced = 1
        }
        { print }
    ' "$RULES" > "${RULES}.tmp" && mv "${RULES}.tmp" "$RULES"
    rm -f "$BLK"

    # ── 4. Prune rules referencing paths absent on this host ──────
    #
    # auditctl validates the path in -F dir=, -F exe= and -w at load time and
    # refuses the rule with:
    #     Error sending add rule data request (No such file or directory)
    #     There was an error in line N of /etc/audit/audit.rules
    #
    # The upstream ruleset ships rules for software that is not installed on a
    # default RHEL host - Filebeat (/etc/filebeat, /usr/share/filebeat),
    # CrowdStrike Falcon (/etc/crowdstrike, /usr/lib/crowdstrike,
    # /opt/CrowdStrike, /var/log/crowdstrike and the falcon-sensor binary),
    # VMware tools (/usr/bin/vmtoolsd) and the LVM lock dir (/var/lock/lvm).
    # Each produces two error lines on every load and every auditd restart,
    # which is noise in the logs of all 70 hosts and makes the loaded rule
    # count disagree with the file for no reason.
    #
    # Deliberately generic rather than a denylist of those names: any rule
    # whose path is missing gets the same treatment, so this keeps working as
    # upstream adds vendors. It is re-evaluated on every run against a freshly
    # downloaded ruleset, so installing the software and re-running restores
    # its rules automatically.
    #
    # This costs no detection coverage: auditctl had already REFUSED these
    # rules, so they were never in the kernel. Pruning only stops the error.
    #
    # It does however make a pre-existing upstream gap visible. Watches on
    # files that do not exist yet - /etc/cron.allow, /etc/cron.deny,
    # /etc/at.allow, /etc/at.deny - are exactly the ones an attacker might
    # CREATE to control who may schedule jobs, and auditd cannot watch a path
    # that is absent. Those events are unmonitored both before and after this
    # change. If that matters in your environment, create the files empty with
    # the correct ownership so the watches load, or add a rule covering
    # creation within /etc rather than the individual filenames.
    local PRUNED=0 line p paths keep
    : > "${RULES}.tmp"
    while IFS= read -r line; do
        keep=1
        if [[ "$line" == -a\ * || "$line" == -w\ * ]]; then
            paths=()
            # -w <path>  (file/directory watch)
            [[ "$line" == -w\ * ]] && paths+=("$(printf '%s' "$line" | awk '{print $2}')")
            # -F dir=<path> and -F exe=<path> (may both appear on one rule)
            if [[ "$line" == *" -F dir="* ]]; then p=${line#*-F dir=}; paths+=("${p%% *}"); fi
            if [[ "$line" == *" -F exe="* ]]; then p=${line#*-F exe=}; paths+=("${p%% *}"); fi
            for p in ${paths+"${paths[@]}"}; do
                # Only absolute paths; strip any trailing slash before testing.
                [[ "$p" == /* ]] || continue
                if [[ ! -e "${p%/}" ]]; then
                    keep=0
                    break
                fi
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

    ok "Volume tuning: cut/narrowed ${n_off} rule(s), added ${N_ADD} scoped rule(s)."
    if (( PRUNED > 0 )); then
        ok "  Pruned ${PRUNED} rule(s) referencing paths not present on this host."
        log "  (Filebeat / CrowdStrike / VMware-tools style rules. Install the"
        log "   software and re-run to restore them.)"
    fi
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

# Enable setroubleshoot for human-readable AVC messages (optional)
if $PKG_MGR list installed setroubleshoot-server &>/dev/null 2>&1; then
    ok "setroubleshoot-server already installed (human-readable AVC messages available)."
else
    log "Installing setroubleshoot-server for human-readable AVC messages..."
    $PKG_MGR install -y setroubleshoot-server 2>/dev/null && \
        ok "setroubleshoot-server installed." || \
        warn "setroubleshoot-server install failed (non-critical)."
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
    warn "Sysmon for Linux skipped (--skip-sysmon)."
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
    check "process_creation kept system-wide" "auditctl -l | grep -q 'execve.*process_creation'"
fi
check "audit.log exists"                   "[[ -f /var/log/audit/audit.log ]]"
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
echo -e "${YELLOW}  1. Deploy RHEL/CentOS inputs.conf to: \$SPLUNK_HOME/etc/system/local/${NC}"
echo -e "${YELLOW}  2. Deploy outputs.conf to:            \$SPLUNK_HOME/etc/system/local/${NC}"
echo -e "${YELLOW}  3. Restart Splunk UF:                 \$SPLUNK_HOME/bin/splunk restart${NC}"
echo -e "${YELLOW}  4. If UF not running as root, ensure $SPLUNK_USER is in adm/wheel group${NC}"
echo -e "${YELLOW}  5. Key log paths for inputs.conf:${NC}"
echo -e "${YELLOW}       /var/log/secure     (SSH/sudo/PAM — NOT auth.log)${NC}"
echo -e "${YELLOW}       /var/log/messages   (syslog — NOT /var/log/syslog)${NC}"
echo -e "${YELLOW}       /var/log/audit/audit.log${NC}"
echo -e "${YELLOW}       /var/log/cron${NC}"
echo -e "${YELLOW}       /var/log/dnf.log or /var/log/yum.log${NC}"
echo ""
