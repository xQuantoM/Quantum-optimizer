# Quantum Server Optimizer (for Linux)

**Version: 1.1**

A Bash script designed to apply general system optimizations and VPN-specific tunings to Linux servers, primarily targeting Debian/Ubuntu-based distributions like Ubuntu 22.04 LTS and 24.04 LTS. It aims for a balance of performance, stability, and broad applicability.

**⚠️ DISCLAIMER: Use this script at your own risk! Always test thoroughly in a non-production environment before applying to critical systems. While the script includes backup mechanisms, ensure you have your own backups and understand the changes being made. The authors are not responsible for any damage or downtime caused by this script.**

## Features

*   **Kernel Parameter Tuning (`sysctl`):**
    *   Optimizes network stack settings (TCP/UDP buffers, queue disciplines).
    *   Enables BBR congestion control (with fallback if unavailable).
    *   Configures `fq_codel` for fair queueing.
    *   Optimizes connection tracking (`nf_conntrack`) for high-connection scenarios (e.g., VPNs).
    *   Enables IP forwarding (essential for VPNs/routers).
    *   Applies various security-related network settings.
    *   Adjusts virtual memory settings (`swappiness`, `dirty_ratio`).
*   **System Resource Limits (`ulimit`):**
    *   Increases default open file descriptor limits for user sessions.
    *   Configured via `/etc/security/limits.d/`.
*   **Module Loading:**
    *   Ensures `tcp_bbr` and `nf_conntrack` modules are loaded and configured to load on boot if used.
*   **IPTables MSS Clamping:**
    *   Adds an `iptables` rule to clamp TCP MSS to PMTU for forwarded traffic, beneficial for VPN tunnels.
    *   **Note:** Persistence for this rule must be configured separately.
*   **Hostname Resolution Fix:**
    *   Attempts to resolve common `sudo: unable to resolve host` errors on Debian/Ubuntu systems.
*   **Backup Mechanism:**
    *   Backs up original versions of modified configuration files (`/etc/sysctl.conf`, `/etc/security/limits.conf`, `/etc/pam.d/common-session`, `/etc/security/limits.d/`) to a timestamped directory in `/etc/script_backups/`.
*   **Idempotency (Partial):**
    *   Designed to be safely re-runnable. It avoids creating duplicate IPTables rules or module load entries if they already exist correctly. Configuration files like `sysctl.conf` are overwritten with the script's defined state.

## Prerequisites

*   **Root Privileges:** The script must be run as root or with `sudo`.
*   **Supported OS:** Primarily tested on Ubuntu 22.04 LTS and 24.04 LTS. Should work on most modern Debian-based systems. Adaptations might be needed for other distributions.
*   **Bash Shell:** The script is written for Bash.
*   **Core Utilities:** Standard Linux utilities like `grep`, `sed`, `awk`, `tee`, `modprobe`, `sysctl`, `iptables`, etc., are expected to be present. `iptables` is required for the MSS clamping feature.

## Configuration Variables

At the top of the `quantum-optimize.sh` script, you can adjust these variables:

*   `SET_BBR_CONGESTION_CONTROL`: `true` (default) or `false`. Whether to attempt to enable BBR congestion control.
*   `FALLBACK_CONGESTION_CONTROL`: `"cubic"` (default). Congestion control algorithm to use if BBR is not enabled or fails.
*   `DISABLE_IPV6`: `false` (default) or `true`. Set to `true` ONLY if you are certain your server does not need IPv6.
*   `ENABLE_VPN_SPECIFIC_TUNING`: `true` (default) or `false`. Enables IP forwarding, conntrack tuning, and MSS clamping. Set to `false` for a generic server not acting as a VPN/router.

## How to Use

1.  **Download the Script:**
    ```bash
    git clone https://github.com/yourusername/your-repo-name.git
    cd your-repo-name
    # OR
    # wget https://raw.githubusercontent.com/yourusername/your-repo-name/main/quantum-optimize.sh
    ```

2.  **Review the Script (Recommended!):**
    Open `quantum-optimize.sh` in a text editor and understand the changes it will make. Adjust the configuration variables at the top if necessary.

3.  **Make it Executable:**
    ```bash
    chmod +x quantum-optimize.sh
    ```

4.  **Run the Script as Root:**
    ```bash
    sudo ./quantum-optimize.sh
    ```

5.  **Follow Post-Script Recommendations:**
    The script will output a list of important recommendations. Pay close attention to these, especially:
    *   **Rebooting the server.**
    *   **Manually configuring firewall rules** for your specific services (e.g., VPN ports, NAT). The script *does not* do this.
    *   **Making IPTables rules persistent** (e.g., using `iptables-persistent`).
    *   **Setting daemon-specific resource limits** via systemd unit files.

## Post-Execution Steps (Crucial!)

1.  **Reboot:**
    ```bash
    sudo reboot
    ```
    This ensures all kernel parameters and PAM limits are fully applied.

2.  **Firewall Configuration (Manual):**
    This script **DOES NOT** configure your firewall (e.g., `iptables`, `nftables`, `ufw`, `firewalld`). You **MUST** manually configure your firewall to:
    *   Allow incoming connections to your service ports (e.g., VPN port UDP 1194).
    *   Allow forwarding of traffic if your server acts as a router/VPN.
    *   Implement NAT/Masquerading if needed (e.g., for VPN clients to share the server's public IP).
    *   **Make your firewall rules persistent!**

3.  **IPTables Persistence (if MSS Clamping was applied):**
    The MSS clamping rule added by the script is not persistent by default. To make it persistent on Debian/Ubuntu:
    ```bash
    sudo apt update && sudo apt install iptables-persistent -y
    sudo netfilter-persistent save
    ```
    Answer "yes" to saving current IPv4 and IPv6 rules if prompted.

4.  **Daemon-Specific Limits:**
    For optimal resource management for your specific services (VPN daemon, web server, database), set `LimitNOFILE` (and other limits as needed) directly in their systemd service unit files.
    Example for a service named `myvpn.service`:
    ```bash
    sudo systemctl edit myvpn.service
    ```
    Add the following lines in the editor:
    ```ini
    [Service]
    LimitNOFILE=16384
    ```
    Save the file, then run:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl restart myvpn.service
    ```

5.  **Monitor Your System:**
    After applying optimizations and rebooting, closely monitor your server's performance, stability, resource usage (CPU, memory, network), and application-specific metrics. Check system logs (`journalctl -xe`, `/var/log/syslog`) for any errors.

## Backups

The script automatically backs up the original versions of:
*   `/etc/sysctl.conf`
*   `/etc/security/limits.conf`
*   `/etc/pam.d/common-session` (and potentially `common-session-noninteractive`)
*   The `/etc/security/limits.d/` directory

These backups are stored in a timestamped subdirectory within `/etc/script_backups/`. For example: `/etc/script_backups/YYYYMMDD_HHMMSS/`.

## Contributing

Contributions, bug reports, and suggestions are welcome! Please open an issue or submit a pull request.
Consider running `shellcheck` on your changes.

