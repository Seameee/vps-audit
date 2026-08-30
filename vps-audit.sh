#!/usr/bin/env bash

VPS_AUDIT_VERSION="0.3.0"

# ------------------------------------------------------------------
# v0.3.0 changes (driven by real-world audits on two VPS):
#   1. SUID check: find now uses -xdev and prunes container/virtual
#      dirs. The old `find /` hung for hours on FUSE cloud mounts
#      (CloudDrive2/OneDrive: every stat is a network round-trip) and
#      Docker overlay storage.
#   2. SSH checks now read the *effective* config via `sshd -T` using
#      the binary that is actually running (readlink /proc/<pid>/exe),
#      so a shadowed/custom sshd earlier in PATH cannot skew results.
#   3. Fail2ban port alignment uses ground truth from `ss -tlnp`
#      (all real sshd listen ports), not just the first `sshd -T` line.
#   4. Port Security now separates Total vs Public (0.0.0.0/[::]/ *)
#      ports and includes UDP; fixes INTERNET_PORTS == PORT_COUNT bug.
#   5. Failed logins use one unified 24h window (journalctl _COMM=sshd).
#   6. iptables/nftables no longer PASS on empty chains/tables.
#   7. Sudo logging check now also looks at /etc/sudoers.d.
#   8. Public IP lookup has --max-time and fallback sources.
#   9. CPU usage parsing made robust against top output variants.
#  10. Audit Summary with PASS/WARN/FAIL counters + exit code
#      (1 when any check FAILs, for CI use).
#  + New checks: PermitEmptyPasswords; inline comments stripped when
#    reading fail2ban jail options.
# ------------------------------------------------------------------

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# -----------------------------------------
# Configuration
# -----------------------------------------

# Static Directory/File Variables
OS_RELEASE_FILE="/etc/os-release"
REBOOT_REQUIRED_FILE="/var/run/reboot-required"
SSH_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
AUTH_LOG_FILE="/var/log/auth.log"
SUDOERS_FILE="/etc/sudoers"
SUDOERS_DIR="/etc/sudoers.d"
PASSWORD_QUALITY_CONF="/etc/security/pwquality.conf"
FAIL2BAN_CONFIG_DIR="/etc/fail2ban"

# Resource Usage Thresholds (Disk/Memory/CPU %)
RESOURCE_WARN=50  # WARN if usage is >= 50%
RESOURCE_FAIL=80  # FAIL if usage is >= 80%

# Running Services Thresholds
SERVICES_WARN=20  # WARN if >= 20 services are running
SERVICES_FAIL=40  # FAIL if >= 40 services are running

# Failed Logins Thresholds (Count, last 24 hours)
LOGINS_WARN=10    # WARN if >= 10 failed logins
LOGINS_FAIL=50    # FAIL if >= 50 failed logins

# Open Ports Thresholds - now applied to PUBLIC (non-loopback) ports
OPEN_PORTS_WARN=10  # WARN if >= 10 public ports
OPEN_PORTS_FAIL=20  # FAIL if >= 20 public ports

# Password Policy
PASSWORD_MINLEN=12  # PASS if pwquality minlen is >= this value

# Report Output Configuration
DEFAULT_REPORT_DIR="."   # Where reports will be saved
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILENAME="vps-audit-report-${TIMESTAMP}.txt"
REPORT_FILE="${DEFAULT_REPORT_DIR}/${REPORT_FILENAME}"

# Ownership
ENABLE_CHOWN=false  # Whether to chown the report (and the report dir, if created)
CHOWN_USER="${SUDO_USER:-$(id -un)}"
REPORT_CHOWN_OWNER="${CHOWN_USER}:$(id -gn "$CHOWN_USER" 2>/dev/null || id -gn)"

# Ensure report directory exists
if [ ! -d "$DEFAULT_REPORT_DIR" ]; then
    if mkdir -p "$DEFAULT_REPORT_DIR"; then
        if [ "$ENABLE_CHOWN" = true ]; then
            if ! chown "$REPORT_CHOWN_OWNER" "$DEFAULT_REPORT_DIR"; then
                echo -e "${RED}[ERROR] Failed to change ownership of ${DEFAULT_REPORT_DIR}.${NC}" >&2
            fi
        fi
    else
        echo -e "${RED}[ERROR] Failed to create directory ${DEFAULT_REPORT_DIR}. Using current directory.${NC}" >&2
        DEFAULT_REPORT_DIR="."
        REPORT_FILE="./${REPORT_FILENAME}"
        ENABLE_CHOWN=false
    fi
fi

# -----------------------------------------
# End Configuration
# -----------------------------------------

# Audit result counters (v0.3)
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

print_header() {
    local header="$1"
    echo -e "\n${BLUE}${BOLD}$header${NC}"
    echo -e "\n$header" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
}

print_info() {
    local label="$1"
    local value="$2"
    echo -e "${BOLD}$label:${NC} $value"
    echo "$label: $value" >> "$REPORT_FILE"
}

# Start the audit
echo -e "${BLUE}${BOLD}VPS Security Audit Tool v${VPS_AUDIT_VERSION}${NC}"
echo -e "${GRAY}https://nuverlabs.com/vps-audit${NC}"
echo -e "${GRAY}Starting audit at $(date)${NC}\n"

echo "VPS Security Audit Tool v${VPS_AUDIT_VERSION}" > "$REPORT_FILE"
echo "https://nuverlabs.com/vps-audit" >> "$REPORT_FILE"
echo "Starting audit at $(date)" >> "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"

# System Information Section
print_header "System Information"

OS_INFO=$(grep PRETTY_NAME "$OS_RELEASE_FILE" 2>/dev/null | cut -d'"' -f2)
KERNEL_VERSION=$(uname -r)
HOSTNAME=$(hostname 2>/dev/null || echo "$HOSTNAME")
UPTIME=$(uptime -p 2>/dev/null || uptime)
UPTIME_SINCE=$(uptime -s 2>/dev/null || echo "unknown")
CPU_INFO=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | xargs)
CPU_CORES=$(nproc 2>/dev/null || echo "?")
TOTAL_MEM=$(free -h | awk '/^Mem:/ {print $2}')
TOTAL_DISK=$(df -h / | awk 'NR==2 {print $2}')
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
    || curl -s --max-time 5 https://ifconfig.me 2>/dev/null \
    || curl -s --max-time 5 https://icanhazip.com 2>/dev/null \
    || echo "unavailable")
LOAD_AVERAGE=$(uptime | awk -F'load average:' '{print $2}' | xargs)

print_info "Hostname" "$HOSTNAME"
print_info "Operating System" "$OS_INFO"
print_info "Kernel Version" "$KERNEL_VERSION"
print_info "Uptime" "$UPTIME (since $UPTIME_SINCE)"
print_info "CPU Model" "$CPU_INFO"
print_info "CPU Cores" "$CPU_CORES"
print_info "Total Memory" "$TOTAL_MEM"
print_info "Total Disk Space" "$TOTAL_DISK"
print_info "Public IP" "$PUBLIC_IP"
print_info "Load Average" "$LOAD_AVERAGE"

echo "" >> "$REPORT_FILE"

# Security Audit Section
print_header "Security Audit Results"

# Function to check and report with three states
check_security() {
    local test_name="$1"
    local status="$2"
    local message="$3"

    case $status in
        "PASS") PASS_COUNT=$((PASS_COUNT+1))
                echo -e "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
                echo "[PASS] $test_name - $message" >> "$REPORT_FILE" ;;
        "WARN") WARN_COUNT=$((WARN_COUNT+1))
                echo -e "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
                echo "[WARN] $test_name - $message" >> "$REPORT_FILE" ;;
        "FAIL") FAIL_COUNT=$((FAIL_COUNT+1))
                echo -e "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
                echo "[FAIL] $test_name - $message" >> "$REPORT_FILE" ;;
    esac
    echo "" >> "$REPORT_FILE"
}

# Check if system requires restart
if [ -f "$REBOOT_REQUIRED_FILE" ]; then
    check_security "System Restart" "WARN" "System requires a restart to apply updates"
else
    check_security "System Restart" "PASS" "No restart required"
fi

# ------------------------------------------------------------------
# SSH effective configuration (v0.3)
# Resolve the sshd binary that is actually running, so a custom sshd
# shadowing PATH (e.g. /usr/local/sbin/sshd) cannot skew the results.
# ------------------------------------------------------------------
SSHD_BIN="/usr/sbin/sshd"
SSHD_PID=$(pgrep -x sshd 2>/dev/null | head -1)
if [ -n "$SSHD_PID" ] && [ -r "/proc/$SSHD_PID/exe" ]; then
    RESOLVED=$(readlink "/proc/$SSHD_PID/exe" 2>/dev/null)
    [ -n "$RESOLVED" ] && [ -x "$RESOLVED" ] && SSHD_BIN="$RESOLVED"
fi

SSHD_EFFECTIVE=""
if [ -x "$SSHD_BIN" ]; then
    SSHD_EFFECTIVE=$("$SSHD_BIN" -T 2>/dev/null)
fi
if [ -z "$SSHD_EFFECTIVE" ]; then
    check_security "SSH Config" "WARN" "Could not read effective sshd config (sshd -T). Falling back to config file parsing."
fi

# Effective value of a single-valued option (first line wins)
sshd_opt() {
    local opt="$1"
    echo "$SSHD_EFFECTIVE" | awk -v o="$opt" '$1==o {print $2; exit}'
}

# All values of a multi-valued option (e.g. Port)
sshd_opt_all() {
    local opt="$1"
    echo "$SSHD_EFFECTIVE" | awk -v o="$opt" '$1==o {print $2}'
}

# Fallback: grep the config files (main + sshd_config.d/*.conf) when
# sshd -T was unavailable. First matching value wins (sshd semantics).
grep_ssh_config() {
    local pattern="$1"
    local files=("$SSH_CONFIG_FILE")
    [ -d "$SSH_CONFIG_DIR" ] && files+=("$SSH_CONFIG_DIR"/*.conf)
    grep -h "^$pattern" "${files[@]}" 2>/dev/null | head -1 | awk '{print $2}'
}

# Check SSH root login (effective config)
SSH_ROOT=$(sshd_opt permitrootlogin)
[ -z "$SSH_ROOT" ] && SSH_ROOT=$(grep_ssh_config "PermitRootLogin")
[ -z "$SSH_ROOT" ] && SSH_ROOT="prohibit-password"
case "$SSH_ROOT" in
    "no") check_security "SSH Root Login" "PASS" "Root login is disabled in the effective SSH configuration" ;;
    "prohibit-password"|"without-password")
          check_security "SSH Root Login" "WARN" "Root login allowed with keys only ($SSH_ROOT) - consider 'PermitRootLogin no'" ;;
    *)    check_security "SSH Root Login" "FAIL" "Root login is currently allowed ($SSH_ROOT) - disable it in $SSH_CONFIG_FILE" ;;
esac

# Check SSH password authentication (effective config)
SSH_PASSWORD=$(sshd_opt passwordauthentication)
[ -z "$SSH_PASSWORD" ] && SSH_PASSWORD=$(grep_ssh_config "PasswordAuthentication")
if [ "$SSH_PASSWORD" = "no" ]; then
    check_security "SSH Password Auth" "PASS" "Password authentication is disabled, key-based auth only"
else
    check_security "SSH Password Auth" "FAIL" "Password authentication is enabled ($SSH_PASSWORD) - consider key-based authentication only"
fi

# Check SSH empty passwords (v0.3 new)
SSH_EMPTY=$(sshd_opt permitemptypasswords)
[ -z "$SSH_EMPTY" ] && SSH_EMPTY="no"
if [ "$SSH_EMPTY" = "no" ]; then
    check_security "SSH Empty Passwords" "PASS" "Empty passwords are not allowed"
else
    check_security "SSH Empty Passwords" "FAIL" "Accounts with empty passwords can log in via SSH - disable empty passwords"
fi

# Check SSH port(s) - all effective Port directives
SSH_PORTS=$(sshd_opt_all port | tr '\n' ' ')
[ -z "$SSH_PORTS" ] && SSH_PORTS=$(grep_ssh_config "Port")
[ -z "$SSH_PORTS" ] && SSH_PORTS="22"
FIRST_SSH_PORT=$(echo "$SSH_PORTS" | awk '{print $1}')
UNPRIVILEGED_PORT_START=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null)
[ -z "$UNPRIVILEGED_PORT_START" ] && UNPRIVILEGED_PORT_START=1024

if ! [[ "$FIRST_SSH_PORT" =~ ^[0-9]+$ ]]; then
    check_security "SSH Port" "WARN" "Could not parse effective SSH port '$FIRST_SSH_PORT'"
elif [ "$FIRST_SSH_PORT" = "22" ]; then
    check_security "SSH Port" "WARN" "Using default port 22 - consider a non-standard port (effective ports: $SSH_PORTS)"
elif [ "$FIRST_SSH_PORT" -ge "$UNPRIVILEGED_PORT_START" ]; then
    check_security "SSH Port" "FAIL" "Using unprivileged port $FIRST_SSH_PORT - a non-root process could bind it if sshd exits (effective ports: $SSH_PORTS)"
else
    check_security "SSH Port" "PASS" "Using non-default port $FIRST_SSH_PORT (effective ports: $SSH_PORTS)"
fi

# Check Firewall Status (v0.3: empty chains/tables no longer PASS)
check_firewall_status() {
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -qw "active"; then
            local policy
            policy=$(ufw status verbose 2>/dev/null | awk '/^Default:/{print $2, $3}')
            check_security "Firewall Status (UFW)" "PASS" "UFW firewall is active (default: $policy)"
        else
            check_security "Firewall Status (UFW)" "FAIL" "UFW is installed but not active - your system is exposed to network attacks"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            check_security "Firewall Status (firewalld)" "PASS" "Firewalld is active and protecting your system"
        else
            check_security "Firewall Status (firewalld)" "FAIL" "Firewalld is not active - your system is exposed to network attacks"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        local rules policy
        rules=$(iptables -S 2>/dev/null | grep -c '^-A')
        policy=$(iptables -L INPUT -n 2>/dev/null | awk 'NR==1 {print $4}')
        if [ "${rules:-0}" -gt 0 ] || [ "$policy" = "DROP" ] || [ "$policy" = "REJECT" ]; then
            check_security "Firewall Status (iptables)" "PASS" "iptables has ${rules:-0} rules and/or $policy INPUT policy"
        else
            check_security "Firewall Status (iptables)" "FAIL" "iptables INPUT chain is empty (policy $policy) - no filtering is happening"
        fi
    elif command -v nft >/dev/null 2>&1; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null | grep -cE '\b(accept|drop|reject|jump|tcp dport|udp dport|ip saddr|iifname)\b')
        if [ "${nft_rules:-0}" -gt 0 ]; then
            check_security "Firewall Status (nftables)" "PASS" "nftables ruleset is active ($nft_rules rule lines)"
        else
            check_security "Firewall Status (nftables)" "FAIL" "nftables ruleset is empty or has no filtering rules"
        fi
    else
        check_security "Firewall Status" "FAIL" "No recognized firewall tool is installed on this system"
    fi
}
check_firewall_status

# Check for unattended upgrades
if command -v dpkg >/dev/null 2>&1 && dpkg -l 2>/dev/null | grep -q "unattended-upgrades"; then
    check_security "Unattended Upgrades" "PASS" "Automatic security updates are configured"
else
    check_security "Unattended Upgrades" "FAIL" "Automatic security updates are not configured - system may miss critical updates"
fi

# Check Intrusion Prevention Systems (Fail2ban or CrowdSec)
# v0.3: docker-not-running WARN is emitted at most once, and only when
# no IPS was found otherwise.
IPS_INSTALLED=0
IPS_ACTIVE=0
IPS_LABEL=""

check_ips_package() {
    local pkg="$1"
    if command -v dpkg >/dev/null 2>&1 && dpkg -l 2>/dev/null | grep -q "$pkg"; then
        IPS_INSTALLED=1
        IPS_LABEL="$pkg"
        systemctl is-active "$pkg" >/dev/null 2>&1 && IPS_ACTIVE=1
    fi
}
check_ips_package "fail2ban"
check_ips_package "crowdsec"

DOCKER_RUNNING=0
if command -v docker >/dev/null 2>&1; then
    systemctl is-active --quiet docker 2>/dev/null && DOCKER_RUNNING=1
fi
if [ "$DOCKER_RUNNING" = 1 ]; then
    for img in fail2ban crowdsec; do
        if docker ps -a 2>/dev/null | awk '{print $2}' | grep -q "$img"; then
            IPS_INSTALLED=1
            IPS_LABEL="$img"
            docker ps 2>/dev/null | grep -q "$img" && IPS_ACTIVE=1
        fi
    done
elif command -v docker >/dev/null 2>&1 && [ "$IPS_INSTALLED" = 0 ]; then
    check_security "Intrusion Prevention" "WARN" "Docker is installed but not running - container-based IPS cannot be checked"
fi

case "$IPS_INSTALLED$IPS_ACTIVE" in
    "11") check_security "Intrusion Prevention" "PASS" "$IPS_LABEL is installed and running" ;;
    "10") check_security "Intrusion Prevention" "WARN" "$IPS_LABEL is installed but not running" ;;
    *)    check_security "Intrusion Prevention" "FAIL" "No intrusion prevention system (Fail2ban or CrowdSec) is installed" ;;
esac

# Resolve a port token to a number. Accepts a numeric port or a service
# name such as "ssh", which fail2ban uses by default.
resolve_port_token() {
    local token="$1"
    if [[ "$token" =~ ^[0-9]+$ ]]; then
        echo "$token"
    else
        getent services "$token" 2>/dev/null | head -1 | awk '{print $2}' | cut -d'/' -f1
    fi
}

# Test whether a fail2ban port list ("ssh", "2022", "ssh,2222", "0:65535")
# covers a specific port number.
port_list_contains() {
    local list="$1" target="$2" token start end resolved
    local IFS=','
    for token in $list; do
        token="${token//[[:space:]]/}"
        [ -z "$token" ] && continue
        if [[ "$token" == *:* ]]; then
            start=$(resolve_port_token "${token%%:*}")
            end=$(resolve_port_token "${token##*:}")
            if [[ "$start" =~ ^[0-9]+$ ]] && [[ "$end" =~ ^[0-9]+$ ]]; then
                if [ "$target" -ge "$start" ] && [ "$target" -le "$end" ]; then
                    return 0
                fi
            fi
        else
            resolved=$(resolve_port_token "$token")
            [ "$resolved" = "$target" ] && return 0
        fi
    done
    return 1
}

# Read an option from a jail section, honouring fail2ban's file
# precedence: jail.conf, jail.d/*.conf, jail.local, jail.d/*.local
# (last wins). Inline comments are stripped (v0.3).
get_jail_option() {
    local section="$1" option="$2" file value result=""
    for file in "$FAIL2BAN_CONFIG_DIR/jail.conf" \
                "$FAIL2BAN_CONFIG_DIR"/jail.d/*.conf \
                "$FAIL2BAN_CONFIG_DIR/jail.local" \
                "$FAIL2BAN_CONFIG_DIR"/jail.d/*.local; do
        [ -f "$file" ] || continue
        value=$(awk -v sect="$section" -v opt="$option" '
            $0 ~ /^[[:space:]]*\[/ {
                in_sect = ($0 ~ "^[[:space:]]*\\[" sect "\\][[:space:]]*$")
                next
            }
            in_sect && $0 ~ "^[[:space:]]*" opt "[[:space:]]*=" {
                sub(/^[^=]*=[[:space:]]*/, "")
                sub(/[[:space:]]+#.*$/, "")
                sub(/[[:space:]]+$/, "")
                val = $0
            }
            END { if (val != "") print val }
        ' "$file" 2>/dev/null)
        [ -n "$value" ] && result="$value"
    done
    echo "$result"
}

# Check that fail2ban's SSH jail actually covers every port the running
# sshd listens on (v0.3: ground truth from `ss -tlnp`, not sshd -T).
check_fail2ban_port_alignment() {
    if ! command -v fail2ban-client >/dev/null 2>&1 || [ ! -d "$FAIL2BAN_CONFIG_DIR" ]; then
        return
    fi

    # Ground truth: ports the running sshd process actually listens on.
    local real_ports
    real_ports=$(ss -tlnH 2>/dev/null | awk '$1=="LISTEN" && $0 ~ /sshd/ {split($4,a,":"); print a[length(a)]}' | sort -nu | tr '\n' ' ')
    # Fallback: effective config ports (already resolved from the running binary)
    if [ -z "$real_ports" ]; then
        real_ports=$(echo "$SSH_PORTS" | tr ' ' '\n' | sort -nu | tr '\n' ' ')
    fi
    if [ -z "$real_ports" ]; then
        check_security "Fail2ban Port Alignment" "WARN" "Could not determine the ports sshd listens on - verify the fail2ban jail port manually"
        return
    fi

    local jail_enabled jail_port jail_banaction
    jail_enabled=$(get_jail_option "sshd" "enabled")
    jail_port=$(get_jail_option "sshd" "port")
    jail_banaction=$(get_jail_option "sshd" "banaction")
    [ -z "$jail_banaction" ] && jail_banaction=$(get_jail_option "DEFAULT" "banaction")
    [ -z "$jail_port" ] && jail_port="ssh"

    if [ "$jail_enabled" != "true" ]; then
        check_security "Fail2ban Port Alignment" "WARN" "The fail2ban [sshd] jail is not enabled - SSH brute force attempts are not being blocked"
        return
    fi

    # An allports banaction blocks every port, so the jail port is irrelevant.
    if [[ "$jail_banaction" == *allports* ]]; then
        check_security "Fail2ban Port Alignment" "PASS" "The fail2ban [sshd] jail bans all ports (banaction=$jail_banaction), so SSH on $real_ports is covered"
        return
    fi

    local p missing=""
    for p in $real_ports; do
        if ! port_list_contains "$jail_port" "$p"; then
            missing="$p"
            break
        fi
    done

    if [ -z "$missing" ]; then
        check_security "Fail2ban Port Alignment" "PASS" "The fail2ban [sshd] jail covers all real sshd ports ($(echo "$real_ports" | tr ' ' ','))"
    else
        check_security "Fail2ban Port Alignment" "FAIL" "The fail2ban [sshd] jail blocks port '$jail_port' but sshd listens on $missing - bans for that port are ineffective. Set 'port = $(echo "$real_ports" | tr ' ' ',')' in $FAIL2BAN_CONFIG_DIR/jail.local, or use banaction = nftables[type=allports]"
    fi
}

# Fail2ban jail port alignment check
check_fail2ban_port_alignment

# Check failed login attempts (v0.3: unified 24h window via journalctl)
FAILED_LOGINS=0
if command -v journalctl >/dev/null 2>&1; then
    FAILED_LOGINS=$(journalctl _COMM=sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Failed password" || true)
    [ -z "$FAILED_LOGINS" ] && FAILED_LOGINS=0
elif [ -f "$AUTH_LOG_FILE" ]; then
    FAILED_LOGINS=$(grep -c "Failed password" "$AUTH_LOG_FILE" 2>/dev/null || true)
    check_security "Auth Log" "WARN" "journalctl unavailable - counted the full $AUTH_LOG_FILE (no 24h window)"
fi

# Ensure FAILED_LOGINS is numeric
FAILED_LOGINS=$(echo "$FAILED_LOGINS" | tr -d '[:space:]')
if ! [[ "$FAILED_LOGINS" =~ ^[0-9]+$ ]]; then
    FAILED_LOGINS=0
fi
FAILED_LOGINS=$((10#$FAILED_LOGINS))

if [ "$FAILED_LOGINS" -lt "$LOGINS_WARN" ]; then
    check_security "Failed Logins" "PASS" "Only $FAILED_LOGINS failed login attempts in the last 24h - within normal range"
elif [ "$FAILED_LOGINS" -lt "$LOGINS_FAIL" ]; then
    check_security "Failed Logins" "WARN" "$FAILED_LOGINS failed login attempts in the last 24h - might indicate breach attempts"
else
    check_security "Failed Logins" "FAIL" "$FAILED_LOGINS failed login attempts in the last 24h - possible brute force attack in progress"
fi

# Check system updates
if command -v apt-get >/dev/null 2>&1; then
    UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d" " -f1)
    [ -z "$UPDATES" ] && UPDATES=0
    if [ "$UPDATES" -eq 0 ]; then
        check_security "System Updates" "PASS" "All system packages are up to date"
    else
        check_security "System Updates" "FAIL" "$UPDATES packages available for upgrade - system may be missing security fixes"
    fi
else
    check_security "System Updates" "WARN" "apt-get not found - update check skipped (non-Debian/Ubuntu system?)"
fi

# Check running services
SERVICES=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | grep -c "running" || true)
SERVICES=${SERVICES:-0}
if [ "$SERVICES" -lt "$SERVICES_WARN" ]; then
    check_security "Running Services" "PASS" "Running minimal services ($SERVICES) - good for security"
elif [ "$SERVICES" -lt "$SERVICES_FAIL" ]; then
    check_security "Running Services" "WARN" "$SERVICES services running - consider reducing attack surface"
else
    check_security "Running Services" "FAIL" "Too many services running ($SERVICES) - increases attack surface"
fi

# Check ports (v0.3: ss preferred, includes UDP, splits Total vs Public)
LISTEN_LINES=""
PORT_TOOLS_OK=0
if command -v ss >/dev/null 2>&1; then
    PORT_TOOLS_OK=1
    LISTEN_LINES=$(ss -tulnH 2>/dev/null | awk '$1=="LISTEN" || $1=="UNCONN"')
elif command -v netstat >/dev/null 2>&1; then
    PORT_TOOLS_OK=1
    LISTEN_LINES=$(netstat -tuln 2>/dev/null | awk '$6=="LISTEN"')
    check_security "Port Scanning" "WARN" "Using netstat (TCP only, no UDP) - consider installing iproute2 (ss)"
fi

if [ "$PORT_TOOLS_OK" = 0 ]; then
    check_security "Port Scanning" "FAIL" "Neither 'ss' nor 'netstat' is available on this system"
else
    ALL_PORTS=""
    PUBLIC_PORTS=""
    if [ -n "$LISTEN_LINES" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local_addr=$(echo "$line" | awk '{print $4}')
            [ -z "$local_addr" ] && continue
            port=$(echo "$local_addr" | awk -F: '{print $NF}')
            case "$port" in
                *[!0-9]*) continue ;;
            esac
            ALL_PORTS="$ALL_PORTS $port"
            addr=$(echo "$local_addr" | sed 's/:[0-9]*$//')
            case "$addr" in
                0.0.0.0|\[::\]|\*) PUBLIC_PORTS="$PUBLIC_PORTS $port" ;;
            esac
        done <<< "$LISTEN_LINES"
    fi

    PORT_COUNT=$(echo "$ALL_PORTS" | tr ' ' '\n' | sort -nu | grep -c . )
    PUBLIC_COUNT=$(echo "$PUBLIC_PORTS" | tr ' ' '\n' | sort -nu | grep -c . )
    PUBLIC_LIST=$(echo "$PUBLIC_PORTS" | tr ' ' '\n' | sort -nu | tr '\n' ',' | sed 's/,$//')
    [ -z "$PUBLIC_LIST" ] && PUBLIC_LIST="none"

    if [ "$PORT_COUNT" -eq 0 ]; then
        check_security "Port Scanning" "WARN" "No listening ports detected - verify with 'ss -tuln'"
    elif [ "$PUBLIC_COUNT" -lt "$OPEN_PORTS_WARN" ]; then
        check_security "Port Security" "PASS" "Good configuration (Total: $PORT_COUNT, Public: $PUBLIC_COUNT): $PUBLIC_LIST"
    elif [ "$PUBLIC_COUNT" -lt "$OPEN_PORTS_FAIL" ]; then
        check_security "Port Security" "WARN" "Review recommended (Total: $PORT_COUNT, Public: $PUBLIC_COUNT): $PUBLIC_LIST"
    else
        check_security "Port Security" "FAIL" "High exposure (Total: $PORT_COUNT, Public: $PUBLIC_COUNT): $PUBLIC_LIST"
    fi
fi

# Check disk space usage
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
DISK_USAGE=$(df -h / | awk 'NR==2 {print int($5)}')
if [ "$DISK_USAGE" -lt "$RESOURCE_WARN" ]; then
    check_security "Disk Usage" "PASS" "Healthy disk space available (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
elif [ "$DISK_USAGE" -lt "$RESOURCE_FAIL" ]; then
    check_security "Disk Usage" "WARN" "Disk space usage is moderate (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
else
    check_security "Disk Usage" "FAIL" "Critical disk space usage (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
fi

# Check memory usage
MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
MEM_USAGE=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
if [ "$MEM_USAGE" -lt "$RESOURCE_WARN" ]; then
    check_security "Memory Usage" "PASS" "Healthy memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
elif [ "$MEM_USAGE" -lt "$RESOURCE_FAIL" ]; then
    check_security "Memory Usage" "WARN" "Moderate memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
else
    check_security "Memory Usage" "FAIL" "Critical memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
fi

# Check CPU usage (v0.3: robust parsing)
CPU_LINE=$(top -bn1 2>/dev/null | grep '%Cpu' | head -1)
if [ -z "$CPU_LINE" ]; then
    CPU_USAGE=0
    CPU_IDLE=0
else
    CPU_USAGE=$(echo "$CPU_LINE" | awk -F',' '{gsub(/[^0-9.]/,"",$1); printf "%.0f", $1}')
    CPU_IDLE=$(echo "$CPU_LINE" | awk -F',' '{gsub(/[^0-9.]/,"",$4); printf "%.0f", $4}')
fi
CPU_CORES=$(nproc 2>/dev/null || echo 1)
CPU_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ')
if [ "$CPU_USAGE" -lt "$RESOURCE_WARN" ]; then
    check_security "CPU Usage" "PASS" "Healthy CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
elif [ "$CPU_USAGE" -lt "$RESOURCE_FAIL" ]; then
    check_security "CPU Usage" "WARN" "Moderate CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
else
    check_security "CPU Usage" "FAIL" "Critical CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
fi

# Check sudo configuration (v0.3: also checks /etc/sudoers.d/)
if grep -rqs "^Defaults.*logfile" "$SUDOERS_FILE" "$SUDOERS_DIR" 2>/dev/null; then
    check_security "Sudo Logging" "PASS" "Sudo commands are being logged for audit purposes"
else
    check_security "Sudo Logging" "FAIL" "Sudo commands are not being logged - add 'Defaults logfile=\"/var/log/sudo.log\"' to /etc/sudoers.d/"
fi

# Check password policy
if [ -f "$PASSWORD_QUALITY_CONF" ]; then
    MINLEN_VALUE=$(grep -E '^[[:space:]]*minlen[[:space:]]*=' "$PASSWORD_QUALITY_CONF" | tail -1 | cut -d= -f2 | tr -d '[:space:]')
    if [ -z "$MINLEN_VALUE" ]; then
        check_security "Password Policy" "FAIL" "No minlen set in $PASSWORD_QUALITY_CONF - system accepts weak passwords"
    elif ! [[ "$MINLEN_VALUE" =~ ^[0-9]+$ ]]; then
        check_security "Password Policy" "WARN" "Could not parse minlen value '$MINLEN_VALUE' in $PASSWORD_QUALITY_CONF"
    elif [ "$MINLEN_VALUE" -ge "$PASSWORD_MINLEN" ]; then
        check_security "Password Policy" "PASS" "Strong password policy is enforced (minlen=$MINLEN_VALUE)"
    else
        check_security "Password Policy" "FAIL" "Weak password policy - minlen=$MINLEN_VALUE is below the recommended $PASSWORD_MINLEN"
    fi
else
    check_security "Password Policy" "FAIL" "No password policy configured - system accepts weak passwords"
fi

# Check for suspicious SUID files (v0.3: fast scan)
COMMON_SUID_PATHS='^/usr/bin/|^/bin/|^/sbin/|^/usr/sbin/|^/usr/lib|^/usr/libexec'
KNOWN_SUID_BINS='ping$|sudo$|mount$|umount$|su$|passwd$|chsh$|newgrp$|gpasswd$|chfn$'

echo -e "\n${GRAY}Checking SUID files (fast scan)...${NC}"
SUID_FILES=$(timeout 180 find / -xdev \
    \( -path /var/lib/docker -o -path /var/lib/containerd -o -path /snap \) -prune -o \
    -type f -perm -4000 -print 2>/dev/null | \
    grep -v -E "$COMMON_SUID_PATHS" | \
    grep -v -E "$KNOWN_SUID_BINS" | \
    wc -l)
SUID_FILES=${SUID_FILES:-0}

if [ "$SUID_FILES" -eq 0 ]; then
    check_security "SUID Files" "PASS" "No suspicious SUID files found - good security practice"
else
    check_security "SUID Files" "WARN" "Found $SUID_FILES SUID files outside standard locations - verify if legitimate"
fi

# Audit summary (v0.3)
print_header "Audit Summary"
print_info "PASS" "$PASS_COUNT"
print_info "WARN" "$WARN_COUNT"
print_info "FAIL" "$FAIL_COUNT"

echo -e "\nVPS audit complete. Full report saved to $REPORT_FILE"
echo -e "Review $REPORT_FILE for detailed recommendations."

echo "================================" >> "$REPORT_FILE"
echo "End of VPS Audit Report" >> "$REPORT_FILE"
echo "Please review all failed checks and implement the recommended fixes." >> "$REPORT_FILE"

# If chown enabled, set ownership of report
if [ "$ENABLE_CHOWN" = true ]; then
    if ! chown "$REPORT_CHOWN_OWNER" "$REPORT_FILE"; then
        echo -e "${RED}[ERROR] Failed to change ownership of ${REPORT_FILE}.${NC}" >&2
    fi
fi

# Exit code for CI: 1 when any check failed
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
