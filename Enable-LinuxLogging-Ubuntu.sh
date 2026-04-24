#!/usr/bin/env bash
# =============================================================================
# Enable-LinuxLogging-Ubuntu.sh
#
# PURPOSE  : Enable all prerequisite logging for Splunk UF collection on
#            Ubuntu 20.04 / 22.04 LTS.
#
# APPLIES  : - auditd installation + Neo23x0 ruleset
#            - auditd.conf tuning (ENRICHED format, log rotation)
#            - rsyslog verification + auth.log / syslog
#            - journald persistent storage
#            - Sysmon for Linux (optional)
#            - Log file permission hardening for Splunk UF read access
#
# SOURCES  : Neo23x0/auditd, MITRE ATT&CK M1047, Red Hat Security Guide,
#            ACSC, Splunk TA-linux_auditd docs
#
# USAGE    :
#   sudo bash Enable-LinuxLogging-Ubuntu.sh [OPTIONS]
#
#   Options:
#     --skip-sysmon          Skip Sysmon for Linux installation
#     --skip-auditd-rules    Skip downloading Neo23x0 rules (use existing)
#     --splunk-user USER     Splunk UF run-as user (default: splunk)
#     --help                 Show this help
#
# REQUIREMENTS : Ubuntu 20.04 or 22.04 LTS, run as root / sudo
# =============================================================================

set -euo pipefail

# ── Defaults ───────────────────────────────────────────────────────
SKIP_SYSMON=false
SKIP_AUDITD_RULES=false
SPLUNK_USER="splunk"
LOG_FILE="/var/log/splunk-prereq-ubuntu-$(date +%Y%m%d_%H%M%S).log"
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

# ── OS check ───────────────────────────────────────────────────────
if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    warn "This script targets Ubuntu. Detected OS may differ — proceeding anyway."
fi

echo ""
echo -e "${BOLD}  Splunk UF Prerequisite — Ubuntu 20.04 / 22.04 LTS${NC}"
echo -e "  Log file: ${LOG_FILE}"
echo ""

# ═══════════════════════════════════════════════════════════════════
# STEP 1: Install auditd
# ═══════════════════════════════════════════════════════════════════
section "STEP 1: Install and Enable auditd"
log "Source: MITRE ATT&CK M1047, Neo23x0/auditd, ACSC"

if dpkg -l auditd &>/dev/null; then
    ok "auditd already installed."
else
    log "Installing auditd and audispd-plugins..."
    apt-get update -qq
    apt-get install -y auditd audispd-plugins
    ok "auditd installed."
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

    if command -v curl &>/dev/null; then
        curl -fsSL "$NEO23X0_RULES_URL" -o /etc/audit/rules.d/audit.rules
    elif command -v wget &>/dev/null; then
        wget -qO /etc/audit/rules.d/audit.rules "$NEO23X0_RULES_URL"
    else
        warn "Neither curl nor wget found. Install one and re-run, or manually place rules at:"
        warn "  /etc/audit/rules.d/audit.rules"
        warn "  Source: $NEO23X0_RULES_URL"
    fi

    if [[ -f /etc/audit/rules.d/audit.rules ]]; then
        ok "Neo23x0 audit rules downloaded to /etc/audit/rules.d/audit.rules"
    fi
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
log "Setting log_format=ENRICHED, increasing log size, configuring rotation"

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

apply_auditd_conf "log_format"              "ENRICHED"
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

# Restart auditd to apply config
systemctl restart auditd
ok "auditd restarted."

# ═══════════════════════════════════════════════════════════════════
# STEP 4: Verify rsyslog and Auth Logging
# ═══════════════════════════════════════════════════════════════════
section "STEP 4: Verify rsyslog and Auth Logging (/var/log/auth.log)"
log "Source: Ubuntu default rsyslog config — auth,authpriv.* → /var/log/auth.log"

if ! systemctl is-active --quiet rsyslog; then
    warn "rsyslog not running — starting..."
    systemctl enable rsyslog
    systemctl start rsyslog
fi
ok "rsyslog is running."

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

# Ensure auth.log and syslog exist
for f in /var/log/auth.log /var/log/syslog /var/log/kern.log; do
    if [[ -f "$f" ]]; then
        ok "Log file exists: $f"
    else
        warn "Log file does not exist yet: $f (will be created on next event)"
    fi
done

# ═══════════════════════════════════════════════════════════════════
# STEP 5: journald Persistent Storage
# ═══════════════════════════════════════════════════════════════════
section "STEP 5: Configure journald Persistent Storage"
log "Prevents log loss on reboot. Source: systemd documentation."

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

# Set reasonable journal size limit
if grep -q "^#SystemMaxUse=" "$JOURNALD_CONF"; then
    sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=2G/' "$JOURNALD_CONF"
else
    echo "SystemMaxUse=2G" >> "$JOURNALD_CONF"
fi

systemctl restart systemd-journald
ok "journald restarted with persistent storage."

# Create journal directory
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
ok "Journal persistence directory: /var/log/journal"

# ═══════════════════════════════════════════════════════════════════
# STEP 6: Cron Logging
# ═══════════════════════════════════════════════════════════════════
section "STEP 6: Ensure Cron Logging is Active"
log "Maps to: T1053.003 (Scheduled Task/Job: Cron)"

# Ubuntu may write cron to syslog rather than a dedicated cron.log
RSYSLOG_CRON="/etc/rsyslog.d/51-cron.conf"
if [[ ! -f "$RSYSLOG_CRON" ]] && ! grep -qr "cron.log" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
    log "Adding dedicated cron log to rsyslog..."
    cat > "$RSYSLOG_CRON" << 'EOF'
# Cron logging for Splunk collection
cron.*    /var/log/cron.log
EOF
    systemctl restart rsyslog
    ok "Cron log configured: /var/log/cron.log"
else
    ok "Cron logging already configured."
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

# ═══════════════════════════════════════════════════════════════════
# STEP 8: Sysmon for Linux (Optional)
# ═══════════════════════════════════════════════════════════════════
section "STEP 8: Sysmon for Linux (Optional)"
log "Source: Microsoft MSTIC — MITRE ATT&CK coverage (T1105, T1071, T1059)"

if [[ "$SKIP_SYSMON" == "true" ]]; then
    warn "Sysmon for Linux skipped (--skip-sysmon)."
else
    if command -v sysmon &>/dev/null; then
        ok "Sysmon for Linux already installed: $(sysmon --version 2>/dev/null || echo 'version unknown')"
    else
        log "Adding Microsoft package repository..."
        UBUNTU_VERSION=$(lsb_release -rs 2>/dev/null || echo "22.04")

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
            warn "Replace with MSTIC config for full ATT&CK coverage:"
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
    if eval "$cmd" &>/dev/null; then
        ok "  PASS: $label"
    else
        err "  FAIL: $label"
    fi
}

check "auditd service running"               "systemctl is-active auditd"
check "auditd rules loaded (>10)"            "[[ \$(auditctl -l 2>/dev/null | wc -l) -gt 10 ]]"
check "log_format=ENRICHED in auditd.conf"   "grep -q 'log_format = ENRICHED' /etc/audit/auditd.conf"
check "audit.log exists"                     "[[ -f /var/log/audit/audit.log ]]"
check "rsyslog service running"              "systemctl is-active rsyslog"
check "auth.log exists"                      "[[ -f /var/log/auth.log ]]"
check "syslog exists"                        "[[ -f /var/log/syslog ]]"
check "kern.log exists"                      "[[ -f /var/log/kern.log ]]"
check "journald persistent storage"          "grep -q 'Storage=persistent' /etc/systemd/journald.conf"
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
echo -e "${YELLOW}  1. Deploy Ubuntu inputs.conf to: \$SPLUNK_HOME/etc/system/local/${NC}"
echo -e "${YELLOW}  2. Deploy outputs.conf to:       \$SPLUNK_HOME/etc/system/local/${NC}"
echo -e "${YELLOW}  3. Restart Splunk UF:            \$SPLUNK_HOME/bin/splunk restart${NC}"
echo -e "${YELLOW}  4. If UF is not running as root, ensure $SPLUNK_USER is in adm group${NC}"
echo ""
