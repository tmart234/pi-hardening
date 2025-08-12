#!/bin/bash

# =================================================================================
# Raspberry Pi Zero 2 W - Security Hardening Script (v4)
#
# Description: This script automates essential security hardening tasks for a
#              Raspberry Pi running Raspberry Pi OS Lite. This version uses a
#              more robust method for updating configuration files.
#
# WARNING: This script will disable password authentication. If you do not
#          configure SSH keys correctly, YOU WILL BE LOCKED OUT.
#
# =================================================================================

# --- Script Functions ---
print_color() {
    case "$1" in
        "green") echo -e "\n\033[0;32m$2\033[0m" ;;
        "red") echo -e "\n\033[0;31m$2\033[0m" ;;
        "yellow") echo -e "\n\033[0;33m$2\033[0m" ;;
        *) echo "$2" ;;
    esac
}

# --- Pre-run Checks ---
if [ "$(id -u)" -ne 0 ]; then
    print_color "red" "This script must be run as root. Please use sudo."
    exit 1
fi

print_color "red" "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
print_color "yellow" "This script will disable password-based SSH login. Ensure you have"
print_color "yellow" "a working SSH key setup before proceeding."
read -p "Do you want to continue? (y/n): " -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_color "green" "Aborting script. No changes were made."
    exit 0
fi

# --- 1. System Update & Upgrade ---
print_color "green" "[TASK 1/8] Updating and upgrading system packages..."
apt-get update && apt-get upgrade -y
print_color "green" "System packages are up to date."

# --- 2. SSH Key Generation (Optional) ---
print_color "green" "[TASK 2/8] SSH Key Generation (Optional)"
read -p "Do you need to generate a new SSH key pair for this machine? (y/n): " -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Enter the username to generate keys for (e.g., pi): " SSH_USER
    if [ -z "$SSH_USER" ] || ! id "$SSH_USER" &>/dev/null; then
        print_color "red" "Invalid or empty username. Aborting key generation."
    else
        USER_HOME=$(getent passwd "$SSH_USER" | cut -d: -f6)
        SSH_DIR="$USER_HOME/.ssh"
        PRIVATE_KEY_PATH="$SSH_DIR/id_rsa"
        PUBLIC_KEY_PATH="$SSH_DIR/id_rsa.pub"
        AUTH_KEYS_PATH="$SSH_DIR/authorized_keys"

        print_color "yellow" "Generating SSH key for user '$SSH_USER'..."
        sudo -u "$SSH_USER" mkdir -p "$SSH_DIR"
        sudo -u "$SSH_USER" ssh-keygen -t rsa -b 4096 -f "$PRIVATE_KEY_PATH" -N ""
        
        # Authorize the new public key for login
        sudo -u "$SSH_USER" cp "$PUBLIC_KEY_PATH" "$AUTH_KEYS_PATH"
        
        chmod 700 "$SSH_DIR"
        chmod 600 "$AUTH_KEYS_PATH"
        chown -R "$SSH_USER:$SSH_USER" "$SSH_DIR"

        print_color "red" "!!!!!!!!!!!!!!!!!!!!!!!! CRITICAL ACTION REQUIRED !!!!!!!!!!!!!!!!!!!!!!!!"
        print_color "yellow" "Your NEW PRIVATE KEY will be displayed below. Copy the ENTIRE key."
        print_color "yellow" "Save it to a file on your computer. You will need this to log in."
        print_color "red" "ONCE YOU PRESS ENTER, THE KEY WILL DISAPPEAR. THIS IS YOUR ONLY CHANCE."
        echo
        cat "$PRIVATE_KEY_PATH"
        echo
        read -p "Press Enter ONLY after you have securely copied the private key..."

        print_color "green" "Key generation complete."
    fi
fi


# --- 3. Configure Firewall (UFW) ---
print_color "green" "[TASK 3/8] Configuring Uncomplicated Firewall (UFW)..."
apt-get install -y ufw

read -p "Enter the SSH port you want to use (e.g., 2222). Press Enter for default (22): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}

print_color "yellow" "Configuring UFW to allow SSH on port $SSH_PORT and HTTPS on port 443..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp
ufw limit "$SSH_PORT"/tcp
ufw allow https # Allow HTTPS on port 443

echo "y" | ufw enable
print_color "green" "UFW has been installed and enabled."
ufw status verbose


# --- 4. Harden SSH Configuration ---
print_color "green" "[TASK 4/8] Hardening SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_BACKUP="/etc/ssh/sshd_config.bak"
TEMP_CONFIG="/tmp/sshd_config.tmp"

cp "$SSHD_CONFIG" "$SSHD_CONFIG_BACKUP"
print_color "yellow" "Backed up sshd_config to $SSHD_CONFIG_BACKUP"

# --- FIX: More reliable method to set SSH config ---
# Use grep to filter out old settings and echo to add new ones.
grep -v -E \
    -e '^#?\s*Port\s+' \
    -e '^#?\s*PermitRootLogin\s+' \
    -e '^#?\s*PasswordAuthentication\s+' \
    -e '^#?\s*ChallengeResponseAuthentication\s+' \
    -e '^#?\s*UsePAM\s+' \
    "$SSHD_CONFIG" > "$TEMP_CONFIG"

# Add the hardened settings to the end of the temp file
{
    echo "" # Add a newline for clarity
    echo "# --- Hardening Script Settings (Applied by script) ---"
    echo "Port $SSH_PORT"
    echo "PermitRootLogin no"
    echo "PasswordAuthentication no"
    echo "PubkeyAuthentication yes"
    echo "ChallengeResponseAuthentication no"
    echo "UsePAM no"
    echo "# --- End of Hardening Script Settings ---"
} >> "$TEMP_CONFIG"

# Replace the original config with the modified temp file
mv "$TEMP_CONFIG" "$SSHD_CONFIG"
chmod 644 "$SSHD_CONFIG"
# --- End of FIX ---

# Validate the new configuration before restarting
sshd -t
if [ $? -ne 0 ]; then
    print_color "red" "FATAL: sshd_config test failed. Restoring backup."
    cp "$SSHD_CONFIG_BACKUP" "$SSHD_CONFIG"
    systemctl restart sshd
    exit 1
fi

systemctl restart sshd
print_color "green" "SSH has been hardened and restarted on port $SSH_PORT."
print_color "yellow" "REMEMBER: Password login is now disabled."


# --- 5. Harden Kernel Parameters (sysctl) ---
print_color "green" "[TASK 5/9] Hardening Kernel Parameters..."
SYSCTL_CONF="/etc/sysctl.d/99-security-hardening.conf"

cat > "$SYSCTL_CONF" << EOF
# --- IP Spoofing Protection ---
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1

# --- Ignore ICMP Broadcast Requests ---
net.ipv4.icmp_echo_ignore_broadcasts = 1

# --- Ignore Bogus ICMP Responses ---
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Log Martian Packets (Spoofed/Incorrectly Routed Packets) ---
net.ipv4.conf.all.log_martians = 1
EOF

sysctl -p "$SYSCTL_CONF"
print_color "green" "Kernel parameters have been hardened."


# --- 6. Install Fail2ban ---
print_color "green" "[TASK 6/8] Installing Fail2ban for brute-force protection..."
apt-get install -y fail2ban
systemctl enable fail2ban && systemctl start fail2ban
print_color "green" "Fail2ban has been installed and is now active."


# --- 7. Set Up Automatic Security Updates ---
print_color "green" "[TASK 7/8] Configuring automatic security updates..."
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
print_color "green" "Unattended-upgrades configured."


# --- 8. Minimize Running Services ---
print_color "green" "[TASK 8/9] Disabling non-essential services..."
systemctl disable --now bluetooth.service
systemctl disable --now avahi-daemon.service
systemctl disable --now avahi-daemon.socket
print_color "green" "Bluetooth and Avahi services have been disabled."


# --- 9. System Cleanup ---
print_color "green" "[TASK 9/9] Cleaning up unused packages..."
apt-get autoremove -y && apt-get clean
print_color "green" "System cleanup complete."


# --- Final Summary ---
print_color "green" "==========================================================="
print_color "green" "            Raspberry Pi Hardening Complete"
print_color "green" "==========================================================="
print_color "yellow" "Summary of changes:"
echo "  - System packages updated."
echo "  - (Optional) New SSH key pair generated."
echo "  - UFW firewall enabled, allowing SSH (port $SSH_PORT) and HTTPS (port 443)."
echo "  - SSH password authentication and root login disabled."
echo "  - Fail2ban installed to block malicious login attempts."
echo "  - Automatic security updates enabled."
echo "  - Bluetooth and Avahi services disabled."
print_color "red" "\nA REBOOT IS REQUIRED to ensure all changes are applied correctly."
read -p "Reboot now? (y/n): " -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_color "green" "Rebooting now..."
    reboot
else
    print_color "yellow" "Please reboot the system manually by typing 'sudo reboot'."
fi

exit 0
