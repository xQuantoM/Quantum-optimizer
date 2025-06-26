#!/bin/bash

# Generic Server & VPN-Aware Optimization Script
# Version: 1.1 (Added robust conntrack handling)
# Aims for a balance of performance, stability, and broad applicability.
# Includes VPN-specific tunables like IP forwarding and conntrack.
# Review settings and test thoroughly on a non-production system first.

# --- Configuration Variables (Adjust as needed) ---
SET_BBR_CONGESTION_CONTROL=true # true or false
FALLBACK_CONGESTION_CONTROL="cubic" # If BBR fails, use this (cubic is common default)
DISABLE_IPV6=false # true or false. Set to true ONLY if you are certain you don't need IPv6.
ENABLE_VPN_SPECIFIC_TUNING=true # true or false. Enables IP forwarding, conntrack, MSS.

# --- Script Execution ---
set -e # Exit immediately if a command exits with a non-zero status.
# set -u # Consider adding: Exit on unset variables (catches typos, but needs careful testing)
# set -o pipefail # Consider adding: Causes a pipeline to return the exit status of the last command in the pipe that failed

echo "🚀 Starting Server & VPN-Aware Optimization (v1.1)..."

# --- 0. Pre-checks and Setup ---
if [ "$(id -u)" -ne 0 ]; then
  echo "❌ This script must be run as root." >&2 # Send errors to stderr
  exit 1
fi

HOSTNAME_VAL=$(hostname)
CURRENT_DATE_TIME=$(date +"%Y%m%d_%H%M%S")

# --- 1. Backup Existing Configurations ---
echo "💾 Backing up critical configuration files..."
SYSCTL_CONF="/etc/sysctl.conf"
LIMITS_CONF="/etc/security/limits.conf"
PAM_COMMON_SESSION="/etc/pam.d/common-session" # Path can vary slightly (e.g. common-session-noninteractive)

# Create backup directory if it doesn't exist
BACKUP_DIR="/etc/script_backups/${CURRENT_DATE_TIME}"
mkdir -p "$BACKUP_DIR"
echo "INFO: Backups will be stored in $BACKUP_DIR"

[ -f "$SYSCTL_CONF" ] && cp -L "$SYSCTL_CONF" "$BACKUP_DIR/sysctl.conf.bak"
[ -f "$LIMITS_CONF" ] && cp -L "$LIMITS_CONF" "$BACKUP_DIR/limits.conf.bak"
[ -f "$PAM_COMMON_SESSION" ] && cp -L "$PAM_COMMON_SESSION" "$BACKUP_DIR/common-session.bak"
# Backup limits.d directory
[ -d "/etc/security/limits.d" ] && cp -LR "/etc/security/limits.d" "$BACKUP_DIR/limits.d.bak"


# --- 2. Attempt to Fix Hostname Resolution (Common sudo issue) ---
echo "⚙️ Checking and attempting to fix hostname resolution for sudo..."
HOSTS_FILE="/etc/hosts"
# Regex to match hostname at start of line or after whitespace, avoiding partial matches
HOSTNAME_REGEX_CHECK="^\s*127\.0\.1\.1\s+.*${HOSTNAME_VAL}\b|^\s*127\.0\.0\.1\s+.*${HOSTNAME_VAL}\b"

if ! grep -qP "$HOSTNAME_REGEX_CHECK" "$HOSTS_FILE"; then
    if grep -q "^\s*127\.0\.1\.1" "$HOSTS_FILE"; then
        echo "INFO: Attempting to add '$HOSTNAME_VAL' to existing 127.0.1.1 line in $HOSTS_FILE."
        # Safer append if sed fails or line is complex
        if ! sudo sed -i.bak_hostname_fix "/^\s*127\.0\.1\.1/ s/\(\s*[^\s]*\)\$/\1 ${HOSTNAME_VAL}/" "$HOSTS_FILE"; then
            echo "WARNING: sed command for hostname fix failed or 127.0.1.1 line not as expected. Appending." >&2
            echo "127.0.1.1       ${HOSTNAME_VAL}" | sudo tee -a "$HOSTS_FILE" > /dev/null
        fi
    else
        echo "INFO: Adding '127.0.1.1 ${HOSTNAME_VAL}' to $HOSTS_FILE."
        echo "127.0.1.1       ${HOSTNAME_VAL}" | sudo tee -a "$HOSTS_FILE" > /dev/null
    fi
    echo "✅ Hostname '$HOSTNAME_VAL' entry adjusted in /etc/hosts. Test sudo functionality after script."
else
    echo "👍 Hostname resolution for '$HOSTNAME_VAL' in /etc/hosts appears okay."
fi

# --- 3. Optimize Kernel Parameters (sysctl) ---
echo "⚙️ Preparing optimized kernel parameters for $SYSCTL_CONF..."

# Determine congestion control
ACTUAL_CONGESTION_CONTROL="$FALLBACK_CONGESTION_CONTROL"
BBR_MODULE_LOADED_BY_SCRIPT=false
if [ "$SET_BBR_CONGESTION_CONTROL" = true ]; then
    echo "INFO: BBR congestion control requested."
    if ! lsmod | grep -q "^tcp_bbr\b"; then # Check if already loaded
        if sudo modprobe tcp_bbr >/dev/null 2>&1; then
            BBR_MODULE_LOADED_BY_SCRIPT=true
            echo "INFO: tcp_bbr module loaded by script."
        else
             echo "WARNING: Failed to load tcp_bbr module." >&2
        fi
    fi

    if sysctl net.ipv4.tcp_available_congestion_control | grep -q "\bbbr\b"; then
        ACTUAL_CONGESTION_CONTROL="bbr"
        echo "INFO: BBR is available. Will be set as default."
        BBR_MODULE_FILE="/etc/modules-load.d/bbr.conf"
        if [ ! -f "$BBR_MODULE_FILE" ] || ! grep -q "^\s*tcp_bbr\s*$" "$BBR_MODULE_FILE"; then
            echo "tcp_bbr" | sudo tee "$BBR_MODULE_FILE" > /dev/null
            echo "INFO: Added tcp_bbr to $BBR_MODULE_FILE for boot loading."
        fi
    else
        echo "WARNING: BBR not listed in available controls, even after attempting modprobe. Using $FALLBACK_CONGESTION_CONTROL." >&2
    fi
else
    echo "INFO: BBR not requested. Using $FALLBACK_CONGESTION_CONTROL."
fi

# Prepare sysctl content
SYSCTL_CONTENT=$(cat <<EOF
# Kernel Parameters Optimized for General Server & VPN Performance
# Timestamp: ${CURRENT_DATE_TIME}
# Script Version: 1.1

fs.file-max = 1048576
net.core.default_qdisc = fq_codel
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.optmem_max = 65536

net.ipv4.tcp_congestion_control = ${ACTUAL_CONGESTION_CONTROL}
net.ipv4.tcp_rmem = 4096 262144 8388608
net.ipv4.tcp_wmem = 4096 262144 8388608
net.ipv4.tcp_mem = 32768 65536 131072
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 131072
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_orphans = 16384

net.ipv4.udp_mem = 32768 65536 131072

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

net.ipv4.neigh.default.gc_thresh1 = 512
net.ipv4.neigh.default.gc_thresh2 = 1024
net.ipv4.neigh.default.gc_thresh3 = 2048
EOF
)

VPN_SYSCTL_ADDITIONS=""
if [ "$ENABLE_VPN_SPECIFIC_TUNING" = true ]; then
    VPN_SYSCTL_ADDITIONS+="\n# VPN Specific Sysctl Settings\n"
    VPN_SYSCTL_ADDITIONS+="net.ipv4.ip_forward = 1\n"
    # VPN_SYSCTL_ADDITIONS+="# net.ipv6.conf.all.forwarding = 1 # Uncomment if using IPv6 VPN and forwarding for IPv6\n"

    # Attempt to load conntrack module if needed
    CONNTRACK_MODULE_LOADED_BY_SCRIPT=false
    if ! lsmod | grep -q "^nf_conntrack\b"; then
        echo "INFO: Attempting to load nf_conntrack module for conntrack settings..."
        if sudo modprobe nf_conntrack >/dev/null 2>&1; then
            CONNTRACK_MODULE_LOADED_BY_SCRIPT=true
            echo "INFO: nf_conntrack module loaded by script."
        else
            echo "WARNING: Failed to load nf_conntrack module." >&2
        fi
    fi
    
    # Check if conntrack sysctl paths exist before adding them
    if [ -e /proc/sys/net/netfilter/nf_conntrack_max ]; then
        VPN_SYSCTL_ADDITIONS+="net.netfilter.nf_conntrack_max = 262144\n"
        VPN_SYSCTL_ADDITIONS+="net.netfilter.nf_conntrack_buckets = 65536\n"
        # VPN_SYSCTL_ADDITIONS+="# net.netfilter.nf_conntrack_tcp_timeout_established = 7200\n"
        
        NF_MODULE_FILE="/etc/modules-load.d/netfilter_conntrack.conf"
        if [ ! -f "$NF_MODULE_FILE" ] || ! grep -q "^\s*nf_conntrack\s*$" "$NF_MODULE_FILE"; then
            echo "nf_conntrack" | sudo tee "$NF_MODULE_FILE" > /dev/null
            echo "INFO: Added nf_conntrack to $NF_MODULE_FILE for boot loading."
        fi
    else
        echo "WARNING: /proc/sys/net/netfilter/nf_conntrack_max not found. Skipping conntrack sysctl settings." >&2
        echo "         Ensure 'nf_conntrack' module is loaded or add it to /etc/modules-load.d/." >&2
    fi
fi
SYSCTL_CONTENT+="${VPN_SYSCTL_ADDITIONS}"


IPV6_SYSCTL_ADDITIONS=""
if [ "$DISABLE_IPV6" = true ]; then
IPV6_SYSCTL_ADDITIONS=$(cat <<EOF_IPV6

# IPv6 Settings (DISABLED by script variable)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF_IPV6
)
else
IPV6_SYSCTL_ADDITIONS=$(cat <<EOF_IPV6

# IPv6 Settings (ENABLED by script variable)
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
EOF_IPV6
)
fi
SYSCTL_CONTENT+="${IPV6_SYSCTL_ADDITIONS}"

VM_SYSCTL_ADDITIONS=$(cat <<EOF_VM

# VM (Virtual Memory) Settings
vm.swappiness = 20
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5
# vm.min_free_kbytes = 65536

# Kernel panic behavior
kernel.panic = 10
# kernel.panic_on_oops = 1
EOF_VM
)
SYSCTL_CONTENT+="${VM_SYSCTL_ADDITIONS}"

echo -e "$SYSCTL_CONTENT" | sudo tee "$SYSCTL_CONF" > /dev/null


echo "🔄 Applying sysctl settings from $SYSCTL_CONF..."
# Run sysctl -p. If it fails, print a warning but don't exit if set -e is active for the whole script.
# This allows the rest of the script to run.
if sudo sysctl -p; then
    echo "✅ Kernel parameters applied successfully."
else
    echo "⚠️ Errors encountered while applying some sysctl settings. Please check $SYSCTL_CONF and kernel logs." >&2
    echo "   The script will continue, but review is needed. Some settings may not have taken effect." >&2
fi

# --- 4. Apply IPTables MSS Clamping (If VPN tuning enabled) ---
if [ "$ENABLE_VPN_SPECIFIC_TUNING" = true ]; then
    echo "⚙️ Applying IPTables MSS Clamping rule for VPN traffic..."
    if ! command -v iptables > /dev/null; then
        echo "WARNING: iptables command not found. Skipping MSS clamping rule. Install with 'sudo apt install iptables'." >&2
    else
        # Check if rule already exists to avoid duplicates
        if ! sudo iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu > /dev/null 2>&1; then
            if sudo iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; then
                echo "✅ IPTables MSS Clamping rule added to FORWARD chain."
                echo "INFO: This rule is NOT persistent by default. You need to use a tool like"
                echo "      'iptables-persistent' (sudo apt install iptables-persistent) and save the rules:"
                echo "      sudo netfilter-persistent save"
                echo "      Or configure your firewall management tool (firewalld, ufw with custom rules)."
            else
                echo "ERROR: Failed to add IPTables MSS Clamping rule." >&2
            fi
        else
            echo "👍 IPTables MSS Clamping rule already seems to exist in FORWARD chain."
        fi
    fi
else
    echo "INFO: VPN specific tuning disabled, skipping MSS clamping rule."
fi


# --- 5. Configure System Resource Limits (ulimit) ---
echo "⚙️ Configuring system resource limits (ulimit)..."
LIMITS_D_FILE="/etc/security/limits.d/99-quantum-optimizations.conf" # Renamed for uniqueness
cat <<EOF | sudo tee "$LIMITS_D_FILE" > /dev/null
# Generic resource limits, primarily for user sessions.
# For critical daemons, configure limits in their systemd service unit or init script.
# Timestamp: ${CURRENT_DATE_TIME}
# Script Version: 1.1

*    soft nofile 65536
*    hard nofile 131072
root soft nofile 65536
root hard nofile 131072
EOF
echo "✅ System resource limits configured in $LIMITS_D_FILE."

# Ensure PAM limits module is active for user sessions
if [ -f "$PAM_COMMON_SESSION" ]; then
    if ! grep -q "^\s*session\s\+required\s\+pam_limits.so" "$PAM_COMMON_SESSION"; then # More precise grep
        echo "session required pam_limits.so" | sudo tee -a "$PAM_COMMON_SESSION" > /dev/null
        echo "🔑 Added pam_limits.so to $PAM_COMMON_SESSION to enable limits.conf."
    else
        echo "👍 pam_limits.so already present in $PAM_COMMON_SESSION."
    fi
else
    # Fallback check for common-session-noninteractive, common on some systems for non-login sessions
    PAM_ALT_SESSION="/etc/pam.d/common-session-noninteractive"
    if [ -f "$PAM_ALT_SESSION" ]; then
        if ! grep -q "^\s*session\s\+required\s\+pam_limits.so" "$PAM_ALT_SESSION"; then
            echo "session required pam_limits.so" | sudo tee -a "$PAM_ALT_SESSION" > /dev/null
            echo "🔑 Added pam_limits.so to $PAM_ALT_SESSION."
        else
            echo "👍 pam_limits.so already present in $PAM_ALT_SESSION."
        fi
    else
        echo "⚠️ $PAM_COMMON_SESSION (and $PAM_ALT_SESSION) not found. Cannot ensure pam_limits.so is loaded." >&2
    fi
fi


# --- 6. Important Post-Script Actions & Recommendations ---
# (Keep this section as is, it's good)
echo ""
echo "🎉 Server & VPN-Aware Optimization script (v1.1) finished."
echo "---------------------------------------------------------------------"
echo "RECOMMENDATIONS & NEXT STEPS:"
echo "---------------------------------------------------------------------"
echo "1. ❗️ REBOOT RECOMMENDED: For all settings (kernel parameters, PAM limits, MSS clamping if applied)"
echo "   to take full effect cleanly across all services, a reboot is highly recommended."
echo "   sudo reboot"
echo ""
echo "2. 🔥 FIREWALL CONFIGURATION (MANUAL):"
echo "   This script DOES NOT configure firewall rules for your VPN (e.g., allow UDP 1194)."
echo "   You MUST configure your firewall (iptables, nftables, ufw, firewalld) to:"
echo "     a) Allow incoming connections to your VPN port(s)."
echo "     b) Allow forwarding of traffic from your VPN interface/clients to the internet."
echo "     c) Implement NAT/Masquerading if your VPN clients use private IPs."
echo "   Example for iptables (not persistent by default):"
echo "     # Replace eth0 with your public interface and 10.8.0.0/24 with your VPN subnet"
echo "     # sudo iptables -A INPUT -i eth0 -p udp --dport 1194 -j ACCEPT"
echo "     # sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT"
echo "     # sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT"
echo "     # sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE"
echo "   Remember to make your firewall rules persistent!"
echo ""
echo "3. 💾 MSS CLAMPING PERSISTENCE (If applied):"
echo "   If the MSS clamping rule was added, ensure it's saved to be active after reboot."
echo "   For Debian/Ubuntu with iptables-persistent:"
echo "     sudo apt update && sudo apt install iptables-persistent -y"
echo "     sudo netfilter-persistent save"
echo ""
echo "4. 🚀 DAEMON-SPECIFIC LIMITS:"
echo "   For your VPN daemon and other critical services (web server, database, etc.):"
echo "   Set resource limits (like 'LimitNOFILE') directly in their systemd service unit files."
echo "   Example for 'myvpn.service': sudo systemctl edit myvpn.service"
echo "     [Service]"
echo "     LimitNOFILE=16384"
echo "   Then: sudo systemctl daemon-reload && sudo systemctl restart myvpn.service"
echo ""
echo "5. 🔬 MONITOR YOUR SYSTEM:"
echo "   After rebooting and configuring your firewall, monitor your system closely."
echo "---------------------------------------------------------------------"

exit 0
