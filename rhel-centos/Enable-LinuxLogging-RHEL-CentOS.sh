#!/usr/bin/env bash
# =============================================================================
# Enable-LinuxLogging-RHEL-CentOS.sh
#
# PURPOSE  : Enable all prerequisite logging for Splunk UF collection on
#            RHEL 8/9 and CentOS 8 Stream.
#
# APPLIES  : - auditd enablement + Neo23x0 ruleset
#            - auditd.conf tuning (ENRICHED format, log rotation)
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
#     --splunk-user USER     Splunk UF run-as user (default: splunk)
#     --help                 Show this help
#
# REQUIREMENTS : RHEL 8/9 or CentOS 8 Stream, run as root / sudo
# =============================================================================

set -euo pipefail

# ── Defaults ───────────────────────────────────────────────────────
SKIP_SYSMON=false
SKIP_AUDITD_RULES=false
SPLUNK_USER="splunk"
LOG_FILE="/var/log/splunk-prereq-rhel-$(date +%Y%m%d_%H%M%S).log"
NEO23X0_RULES_URL="https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules"

# ── Colours ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

# ── Parse args ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-sysmon)       SKIP_SYSMON=true        ;;
        --skip-auditd-rules) SKIP_AUDITD_RULES=true  ;;
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

if rpm -q audit &>/dev/null; then
    ok "audit package already installed."
else
    log "Installing audit and audit-libs..."
    $PKG_MGR install -y audit audit-libs
    ok "auditd installed."
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

    if command -v curl &>/dev/null; then
        curl -fsSL "$NEO23X0_RULES_URL" -o /etc/audit/rules.d/audit.rules
    elif command -v wget &>/dev/null; then
        wget -qO /etc/audit/rules.d/audit.rules "$NEO23X0_RULES_URL"
    else
        err "Neither curl nor wget available."
        warn "Manually download rules from: $NEO23X0_RULES_URL"
        warn "Place at: /etc/audit/rules.d/audit.rules"
    fi

    [[ -f /etc/audit/rules.d/audit.rules ]] && \
        ok "Neo23x0 rules downloaded to /etc/audit/rules.d/audit.rules"
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
log "Setting log_format=ENRICHED, rotation, and disk-space thresholds"

AUDITD_CONF="/etc/audit/auditd.conf"

apply_auditd_conf() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}" "$AUDITD_CONF"; then
        sed -i "s|^${key}.*|${key} = ${value}|" "$AUDITD_CONF"
    else
        echo "${key} = ${value}" >> "$AUDITD_CONF"
    fi
    log "  auditd.conf: ${key} = ${value}"
}

apply_auditd_conf "log_format"               "ENRICHED"
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
ok "auditd restarted."

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

if grep -q "^Storage=persistent" "$JOURNALD_CONF"; then
    ok "journald Storage=persistent already set."
else
    if grep -q "^#Storage=" "$JOURNALD_CONF"; then
        sed -i 's/^#Storage=.*/Storage=persistent/' "$JOURNALD_CONF"
    elif grep -q "^Storage=" "$JOURNALD_CONF"; then
        sed -i 's/^Storage=.*/Storage=persistent/' "$JOURNALD_CONF"
    else
        echo "Storage=persistent" >> "$JOURNALD_CONF"
    fi
    ok "journald Storage=persistent set."
fi

if grep -q "^#SystemMaxUse=" "$JOURNALD_CONF"; then
    sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=2G/' "$JOURNALD_CONF"
else
    grep -q "^SystemMaxUse=" "$JOURNALD_CONF" || echo "SystemMaxUse=2G" >> "$JOURNALD_CONF"
fi

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
    if eval "$cmd" &>/dev/null; then
        ok "  PASS: $label"
    else
        err "  FAIL: $label"
    fi
}

check "auditd service running"              "systemctl is-active auditd"
check "auditd rules loaded (>10)"           "[[ \$(auditctl -l 2>/dev/null | wc -l) -gt 10 ]]"
check "log_format=ENRICHED in auditd.conf" "grep -q 'log_format = ENRICHED' /etc/audit/auditd.conf"
check "audit.log exists"                   "[[ -f /var/log/audit/audit.log ]]"
check "rsyslog running"                    "systemctl is-active rsyslog"
check "/var/log/secure exists"             "[[ -f /var/log/secure ]]"
check "/var/log/messages exists"           "[[ -f /var/log/messages ]]"
check "/var/log/cron exists"               "[[ -f /var/log/cron ]]"
check "journald persistent storage"        "grep -q 'Storage=persistent' /etc/systemd/journald.conf"
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
