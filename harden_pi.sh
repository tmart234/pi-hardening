#!/bin/bash
# =================================================================================
# Raspberry Pi Zero 2 W - Security Hardening Script (v6)
#
# Targets Raspberry Pi OS Lite (Bookworm / Trixie, 32- or 64-bit). Also works on
# older releases and other Pi models, but defaults are tuned for the Zero 2 W:
#   - 512 MB RAM and slow SD storage: lean package installs, no extra daemons.
#   - Wi-Fi is usually the ONLY network link: it is never touched.
#   - Bluetooth is disabled at the firmware level (dtoverlay=disable-bt).
#
# All questions are asked up front, so the long apt upgrade (often 20+ minutes
# on a Zero 2 W) and everything after it run unattended.
#
# Non-interactive use: set any of the variables below in the environment and
# pass -y to accept defaults for the rest, e.g.
#   sudo SSH_PORT=2222 EXTRA_TCP_PORTS="443" ./harden_pi.sh -y
#
# WARNING: Password SSH login is disabled. The script refuses to continue unless
#          the chosen user already has an SSH public key installed (or you paste
#          one in), but always keep your current session open and test a NEW
#          login before you log out.
# =================================================================================

set -Eeuo pipefail

SCRIPT_VERSION="6"
LOG_FILE="/var/log/pi-hardening.log"
STAMP="$(date +%Y%m%d-%H%M%S)"
SSHD_DROPIN="/etc/ssh/sshd_config.d/00-pi-hardening.conf"
SYSCTL_CONF="/etc/sysctl.d/99-pi-hardening.conf"
F2B_JAIL="/etc/fail2ban/jail.d/zz-pi-hardening.local"
UU_CONF="/etc/apt/apt.conf.d/52pi-hardening-unattended-upgrades"
MODPROBE_CONF="/etc/modprobe.d/pi-hardening.conf"
JOURNALD_CONF="/etc/systemd/journald.conf.d/pi-hardening.conf"

# --- Tunables (environment overrides; prompted for when unset) -------------------
ASSUME_YES="${ASSUME_YES:-no}"
SSH_USER="${SSH_USER:-}"
SSH_PORT="${SSH_PORT:-}"
EXTRA_TCP_PORTS="${EXTRA_TCP_PORTS-__ask__}"   # e.g. "443 8080"; empty = none
INSTALL_FAIL2BAN="${INSTALL_FAIL2BAN:-}"
DISABLE_BLUETOOTH="${DISABLE_BLUETOOTH:-}"
DISABLE_AVAHI="${DISABLE_AVAHI:-}"
SUDO_REQUIRE_PASSWORD="${SUDO_REQUIRE_PASSWORD:-}"
AUTO_REBOOT_UPDATES="${AUTO_REBOOT_UPDATES:-}"
BLOCK_USB_STORAGE="${BLOCK_USB_STORAGE:-}"
TMPFS_TMP="${TMPFS_TMP:-}"
DISABLE_CLOUD_INIT="${DISABLE_CLOUD_INIT:-}"
LOCK_ROOT_PASSWORD="${LOCK_ROOT_PASSWORD:-}"

# --- Helpers ---------------------------------------------------------------------
print_color() {
    case "$1" in
        green)  echo -e "\n\033[0;32m$2\033[0m" ;;
        red)    echo -e "\n\033[0;31m$2\033[0m" ;;
        yellow) echo -e "\n\033[0;33m$2\033[0m" ;;
        *)      echo "$2" ;;
    esac
}
info() { print_color yellow "$1"; }
ok()   { print_color green "$1"; }
die()  { print_color red "ERROR: $1"; exit 1; }
task() { print_color green "[TASK $1/$TOTAL_TASKS] $2"; }

trap 'print_color red "Script failed at line $LINENO (exit $?). See $LOG_FILE."' ERR

# ask_yn VAR "question" default(y|n)  -> sets VAR to yes|no unless already set
ask_yn() {
    local var="$1" question="$2" default="$3" reply
    [ -n "${!var}" ] && return 0
    if [ "$ASSUME_YES" = yes ]; then
        reply="$default"
    else
        local hint="[y/N]"; [ "$default" = y ] && hint="[Y/n]"
        read -r -p "$question $hint: " reply
        reply="${reply:-$default}"
    fi
    if [[ $reply =~ ^[Yy] ]]; then printf -v "$var" yes; else printf -v "$var" no; fi
}

# ask VAR "question" default  -> free-text answer
ask() {
    local var="$1" question="$2" default="$3" reply
    if [ "$ASSUME_YES" = yes ]; then
        reply="$default"
    else
        read -r -p "$question [${default:-none}]: " reply
        reply="${reply:-$default}"
    fi
    printf -v "$var" '%s' "$reply"
}

backup() { [ -e "$1" ] && cp -a "$1" "$1.bak-$STAMP" && info "Backed up $1 -> $1.bak-$STAMP"; return 0; }

count_keys() {
    [ -f "$1" ] || { echo 0; return; }
    grep -cE '(^|[[:space:]])(ssh-(ed25519|rsa|dss)|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)[[:space:]]+AAAA' "$1" || true
}

valid_port() { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

# --- Arguments -------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes) ASSUME_YES=yes ;;
        -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
        *) die "Unknown argument: $1 (use -h for help)" ;;
    esac
    shift
done

# =================================================================================
# Pre-flight checks and questions (no changes are made in this section)
# =================================================================================
[ "$(id -u)" -eq 0 ] || die "This script must be run as root. Please use sudo."
command -v apt-get >/dev/null || die "apt-get not found; this script targets Raspberry Pi OS / Debian."

exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== pi-hardening v$SCRIPT_VERSION run started $(date -Is) ==="

MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo unknown)"
# shellcheck disable=SC1091
. /etc/os-release
info "Detected: $MODEL / ${PRETTY_NAME:-unknown OS}"
if [[ $MODEL != *"Zero 2 W"* ]]; then
    info "This script is tuned for the Raspberry Pi Zero 2 W but will run on other boards."
fi

BOOT_CONFIG=""
for f in /boot/firmware/config.txt /boot/config.txt; do
    [ -f "$f" ] && { BOOT_CONFIG="$f"; break; }
done

print_color red "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
info "This script disables password-based SSH login and root login over SSH."
info "Keep this session open and test a new SSH login before logging out."
if [ "$ASSUME_YES" != yes ]; then
    read -r -p "Do you want to continue? (y/n): " REPLY
    [[ $REPLY =~ ^[Yy]$ ]] || { ok "Aborting. No changes were made."; exit 0; }
fi

# --- SSH user and key check (lockout prevention) ---
if [ -z "$SSH_USER" ]; then
    DEFAULT_USER="${SUDO_USER:-}"
    [ "$DEFAULT_USER" = root ] && DEFAULT_USER=""
    ask SSH_USER "User that will log in over SSH" "$DEFAULT_USER"
fi
[ -n "$SSH_USER" ] && [ "$SSH_USER" != root ] || die "A non-root SSH user is required."
id "$SSH_USER" &>/dev/null || die "User '$SSH_USER' does not exist."
USER_HOME="$(getent passwd "$SSH_USER" | cut -d: -f6)"
AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"

if [ "$(count_keys "$AUTH_KEYS")" -eq 0 ]; then
    print_color red "No SSH public key found in $AUTH_KEYS."
    info "Generate a key on YOUR computer (not the Pi), e.g.:  ssh-keygen -t ed25519"
    info "then either run 'ssh-copy-id $SSH_USER@<pi-address>' from that computer, or paste"
    info "the contents of ~/.ssh/id_ed25519.pub below."
    [ "$ASSUME_YES" = yes ] && die "Refusing to disable password login without an authorized key."
    read -r -p "Paste public key (or press Enter to abort): " PUBKEY
    [ -n "$PUBKEY" ] || die "Aborted. No changes were made."
    TMPKEY="$(mktemp)"
    printf '%s\n' "$PUBKEY" > "$TMPKEY"
    ssh-keygen -l -f "$TMPKEY" >/dev/null 2>&1 || { rm -f "$TMPKEY"; die "That does not look like a valid SSH public key."; }
    install -d -m 700 -o "$SSH_USER" -g "$(id -gn "$SSH_USER")" "$USER_HOME/.ssh"
    cat "$TMPKEY" >> "$AUTH_KEYS"
    rm -f "$TMPKEY"
    chown "$SSH_USER:$(id -gn "$SSH_USER")" "$AUTH_KEYS"
    chmod 600 "$AUTH_KEYS"
    ok "Key added to $AUTH_KEYS."
fi
ok "Found $(count_keys "$AUTH_KEYS") SSH key(s) for '$SSH_USER'."

# --- Remaining questions ---
if [ -z "$SSH_PORT" ]; then
    ask SSH_PORT "SSH port" "22"
fi
valid_port "$SSH_PORT" || die "Invalid SSH port: $SSH_PORT"

if [ "$EXTRA_TCP_PORTS" = "__ask__" ]; then
    ask EXTRA_TCP_PORTS "Additional inbound TCP ports to open, space-separated (e.g. 443)" ""
fi
for p in $EXTRA_TCP_PORTS; do valid_port "$p" || die "Invalid port in EXTRA_TCP_PORTS: $p"; done

ask_yn INSTALL_FAIL2BAN "Install fail2ban (~40 MB RAM; UFW rate limiting is applied either way)?" y
ask_yn DISABLE_BLUETOOTH "Disable Bluetooth (firmware-level, frees the UART)?" y
ask_yn DISABLE_AVAHI "Disable Avahi/mDNS? (you will no longer reach the Pi as <hostname>.local)" n
ask_yn AUTO_REBOOT_UPDATES "Allow unattended-upgrades to reboot at 04:00 when a kernel update needs it?" n
ask_yn BLOCK_USB_STORAGE "Block USB mass storage? (USB sticks/drives will stop working)" n

if [ "$(findmnt -n -o FSTYPE /tmp 2>/dev/null)" = tmpfs ] || awk '$2=="/tmp"{f=1} END{exit !f}' /etc/fstab; then
    TMPFS_TMP=already
else
    ask_yn TMPFS_TMP "Put /tmp in RAM (tmpfs, max 25% of RAM; less SD wear, cleared on reboot)?" y
fi

if command -v cloud-init >/dev/null && [ ! -e /etc/cloud/cloud-init.disabled ]; then
    CI_STATUS="$(cloud-init status 2>/dev/null || true)"   # non-zero exit for "degraded done"
    if grep -q 'status: done' <<<"$CI_STATUS"; then
        ask_yn DISABLE_CLOUD_INIT "cloud-init finished first-boot setup. Disable it so it stops running on every boot?" y
    else
        info "cloud-init has not reported 'done'; leaving it enabled."
        DISABLE_CLOUD_INIT=no
    fi
else
    DISABLE_CLOUD_INIT=n/a
fi

if passwd -S root 2>/dev/null | awk '{exit !($2=="P")}'; then
    if grep -qw sudo <<<"$(id -nG "$SSH_USER")"; then
        ask_yn LOCK_ROOT_PASSWORD "root has a password set. Lock it (use sudo instead)?" y
    else
        info "root has a password, but '$SSH_USER' is not in the sudo group, so root is left unlocked."
        LOCK_ROOT_PASSWORD=no
    fi
else
    LOCK_ROOT_PASSWORD=n/a
fi

SUDO_NOPASSWD_FILES="$(grep -lsE "^[[:space:]]*${SSH_USER}[[:space:]].*NOPASSWD" /etc/sudoers.d/* || true)"
if [ -n "$SUDO_NOPASSWD_FILES" ]; then
    if passwd -S "$SSH_USER" 2>/dev/null | awk '{exit !($2=="P")}'; then
        ask_yn SUDO_REQUIRE_PASSWORD "'$SSH_USER' can sudo WITHOUT a password. Require the account password for sudo?" y
    else
        info "'$SSH_USER' has passwordless sudo but no usable password, so it is left as-is."
        info "Set one with 'sudo passwd $SSH_USER' and re-run to require it for sudo."
        SUDO_REQUIRE_PASSWORD=no
    fi
else
    SUDO_REQUIRE_PASSWORD=no
fi

TOTAL_TASKS=10
ok "All questions answered. The rest runs unattended."

# =================================================================================
# 1. System update
# =================================================================================
task 1 "Updating system packages (this is slow on a Zero 2 W; be patient)..."
export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
apt-get update
# full-upgrade is what Raspberry Pi recommends: it pulls in new kernel/firmware packages.
apt-get "${APT_OPTS[@]}" full-upgrade
PKGS=(ufw unattended-upgrades)
[ "$INSTALL_FAIL2BAN" = yes ] && PKGS+=(fail2ban python3-systemd)
# --no-install-recommends keeps the footprint small on 512 MB RAM / SD storage.
apt-get "${APT_OPTS[@]}" install --no-install-recommends "${PKGS[@]}"
ok "Packages up to date."

# =================================================================================
# 2. SSH hardening
# =================================================================================
task 2 "Hardening SSH..."
SSHD_CONFIG=/etc/ssh/sshd_config
backup "$SSHD_CONFIG"

# Remove the block that v4 of this script appended (it set "UsePAM no", which
# breaks PAM session/account handling on Debian).
sed -i '/^# --- Hardening Script Settings (Applied by script) ---$/,/^# --- End of Hardening Script Settings ---$/d' "$SSHD_CONFIG"

# Use a drop-in. sshd uses the FIRST value it sees and sshd_config includes
# sshd_config.d/*.conf at the top, so lines appended to the end of sshd_config are
# overridden by drop-ins such as 50-cloud-init.conf ("PasswordAuthentication yes"),
# which Raspberry Pi Imager creates. A "00-" drop-in is read before all of them.
mkdir -p /etc/ssh/sshd_config.d
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONFIG"
fi

# "Port" is cumulative (every Port line adds a listener), so comment out any
# active Port lines in sshd_config itself; the drop-in sets the only one.
sed -i -E 's/^([[:space:]]*Port[[:space:]])/#\1/' "$SSHD_CONFIG"

OPENSSH_VER="$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9]*\.[0-9]*\).*/\1/p')"
KBD_OPT="KbdInteractiveAuthentication"
if [ -n "$OPENSSH_VER" ] && [ "$(printf '%s\n8.7\n' "$OPENSSH_VER" | sort -V | head -1)" != "8.7" ]; then
    KBD_OPT="ChallengeResponseAuthentication"   # OpenSSH < 8.7 (Bullseye and older)
fi

backup "$SSHD_DROPIN"
cat > "$SSHD_DROPIN" <<EOF
# Managed by pi-hardening v$SCRIPT_VERSION ($STAMP). Re-run the script to change.
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
$KBD_OPT no
AuthenticationMethods publickey
UsePAM yes
AllowUsers $SSH_USER
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 10:30:60
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
chmod 644 "$SSHD_DROPIN"

restore_ssh() {
    print_color red "sshd validation failed; restoring previous configuration."
    if [ -e "$SSHD_DROPIN.bak-$STAMP" ]; then mv "$SSHD_DROPIN.bak-$STAMP" "$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
    cp -a "$SSHD_CONFIG.bak-$STAMP" "$SSHD_CONFIG"
    exit 1
}

mkdir -p /run/sshd
sshd -t || restore_ssh
# Verify the EFFECTIVE config, so a conflicting drop-in can never silently win.
EFFECTIVE="$(sshd -T -C "user=$SSH_USER,host=localhost,addr=127.0.0.1")" || restore_ssh
for want in "passwordauthentication no" "permitrootlogin no" "port $SSH_PORT" "pubkeyauthentication yes"; do
    grep -qx "$want" <<<"$EFFECTIVE" || { print_color red "Effective sshd setting is not '$want'."; restore_ssh; }
done
if [ "$(grep -c '^port ' <<<"$EFFECTIVE")" -ne 1 ]; then
    print_color red "sshd would listen on several ports: $(grep '^port ' <<<"$EFFECTIVE" | tr '\n' ' ')"
    info "Remove the extra Port lines from /etc/ssh/sshd_config.d/*.conf and re-run."
    restore_ssh
fi

SSH_UNIT=ssh
systemctl cat ssh.service &>/dev/null || SSH_UNIT=sshd
# With socket activation the listening port comes from ssh.socket, not sshd_config.
if systemctl is-enabled ssh.socket &>/dev/null; then
    info "ssh.socket activation detected; switching to ssh.service so the Port setting applies."
    systemctl disable --now ssh.socket
    systemctl enable "$SSH_UNIT"
fi
systemctl restart "$SSH_UNIT"
ok "SSH hardened (port $SSH_PORT, keys only, user '$SSH_USER' only). Existing sessions stay open."

# =================================================================================
# 3. Firewall
# =================================================================================
task 3 "Configuring UFW firewall..."
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw limit "$SSH_PORT/tcp" comment 'SSH (rate limited)'
for p in $EXTRA_TCP_PORTS; do
    ufw allow "$p/tcp" comment 'pi-hardening extra port'
done
# Note: UFW's default before.rules already accept mDNS (5353/udp multicast) and DHCP replies.
ufw --force enable
ufw status verbose
ok "Firewall enabled."

# =================================================================================
# 4. Fail2ban
# =================================================================================
task 4 "Configuring fail2ban..."
if [ "$INSTALL_FAIL2BAN" = yes ]; then
    # Bookworm+ has no /var/log/auth.log (journald only), so the stock sshd jail
    # cannot start unless the systemd backend is used.
    cat > "$F2B_JAIL" <<EOF
# Managed by pi-hardening v$SCRIPT_VERSION
[DEFAULT]
backend = systemd
banaction = ufw
banaction_allports = ufw
bantime = 1h
bantime.increment = true
findtime = 10m
maxretry = 5
# Keep the SQLite database small on the SD card.
dbpurgeage = 2d

[sshd]
enabled = true
port = $SSH_PORT
EOF
    systemctl enable fail2ban
    systemctl restart fail2ban
    sleep 2
    fail2ban-client status sshd || info "fail2ban did not report the sshd jail yet; check 'sudo fail2ban-client status sshd'."
    ok "fail2ban active."
else
    info "Skipped (UFW 'limit' still rate-limits SSH)."
fi

# =================================================================================
# 5. Kernel parameters
# =================================================================================
task 5 "Hardening kernel parameters and modules..."
# A leading '-' makes systemd-sysctl (used at boot) ignore keys this kernel lacks;
# 'sysctl -e' does the same for the immediate apply below.
cat > "$SYSCTL_CONF" <<'EOF'
# Managed by pi-hardening
# --- Network ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
-net.ipv6.conf.all.accept_redirects = 0
-net.ipv6.conf.default.accept_redirects = 0
-net.ipv6.conf.all.accept_source_route = 0
-net.ipv6.conf.default.accept_source_route = 0
# --- Kernel ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
-kernel.unprivileged_bpf_disabled = 1
-net.core.bpf_jit_harden = 2
-kernel.yama.ptrace_scope = 1
-kernel.kexec_load_disabled = 1
# --- Filesystem ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
sysctl -e -q -p "$SYSCTL_CONF" || info "Some sysctl keys could not be applied on this kernel (see above)."
ok "Kernel parameters applied."

# Rarely used network protocols and filesystems with a history of kernel bugs.
# "install <mod> /bin/false" also stops them being auto-loaded on demand.
{
    echo "# Managed by pi-hardening v$SCRIPT_VERSION"
    for m in dccp sctp rds tipc cramfs freevxfs hfs hfsplus jffs2 udf; do
        echo "install $m /bin/false"
        echo "blacklist $m"
    done
    if [ "$BLOCK_USB_STORAGE" = yes ]; then
        echo "# USB mass storage (the OTG port is the main physical attack surface)"
        echo "install usb-storage /bin/false"
        echo "install uas /bin/false"
        echo "blacklist usb-storage"
        echo "blacklist uas"
    fi
} > "$MODPROBE_CONF"
LOADED_MODULES="$(lsmod 2>/dev/null || true)"
for m in dccp sctp rds tipc cramfs freevxfs hfs hfsplus jffs2 udf; do
    if grep -q "^$m " <<<"$LOADED_MODULES"; then
        info "Module $m is currently loaded; it will stay loaded until reboot."
    fi
done
ok "Unused kernel modules blocked ($MODPROBE_CONF)."

# =================================================================================
# 6. Automatic security updates
# =================================================================================
task 6 "Configuring unattended-upgrades..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
# Debian's defaults only match Debian origins. Raspberry Pi OS also needs:
#  - "Raspberry Pi Foundation" (archive.raspberrypi.com: kernel, firmware, Pi tools)
#  - "Raspbian" (32-bit OS: every package comes from here, so without this
#    unattended-upgrades installs nothing at all)
cat > "$UU_CONF" <<EOF
// Managed by pi-hardening v$SCRIPT_VERSION
Unattended-Upgrade::Origins-Pattern {
        "origin=Raspberry Pi Foundation,codename=\${distro_codename}";
        "origin=Raspbian,codename=\${distro_codename}";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$([ "$AUTO_REBOOT_UPDATES" = yes ] && echo true || echo false)";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
if unattended-upgrade --dry-run >/dev/null 2>&1; then
    ok "unattended-upgrades configured (dry run OK)."
else
    info "unattended-upgrades dry run reported a problem; check 'sudo unattended-upgrade --dry-run -d'."
fi

# =================================================================================
# 7. Minimize services / radios
# =================================================================================
task 7 "Disabling non-essential services..."
disable_unit() {
    if systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1"; then
        systemctl disable --now "$1" &>/dev/null || true
        echo "  disabled $1"
    fi
}
if [ "$DISABLE_BLUETOOTH" = yes ]; then
    disable_unit bluetooth.service
    disable_unit hciuart.service
    if [ -n "$BOOT_CONFIG" ]; then
        if ! grep -qE '^[[:space:]]*dtoverlay=(pi3-)?disable-bt' "$BOOT_CONFIG"; then
            backup "$BOOT_CONFIG"
            # Add under an explicit [all] so it is not swallowed by a model-specific section.
            printf '\n[all]\n# Added by pi-hardening: turn off the Bluetooth radio\ndtoverlay=disable-bt\n' >> "$BOOT_CONFIG"
            echo "  added dtoverlay=disable-bt to $BOOT_CONFIG (takes effect after reboot)"
        fi
    else
        info "Could not find config.txt; Bluetooth radio is only disabled in software."
    fi
fi
if [ "$DISABLE_AVAHI" = yes ]; then
    disable_unit avahi-daemon.socket
    disable_unit avahi-daemon.service
fi
if [ "$DISABLE_CLOUD_INIT" = yes ]; then
    # Settings it already applied (user, Wi-Fi via netplan/NetworkManager, SSH) stay in place.
    touch /etc/cloud/cloud-init.disabled
    echo "  disabled cloud-init (re-enable: sudo rm /etc/cloud/cloud-init.disabled)"
fi
# Never disable Wi-Fi here: on a Zero 2 W it is usually the only network link.
ok "Services minimized."

# =================================================================================
# 8. sudo
# =================================================================================
task 8 "Hardening accounts, console and sudo..."
# Console autologin (raspi-config "Console Autologin") gives a root-capable shell
# to anyone who plugs in a keyboard and monitor.
AUTOLOGIN_FILES="$(grep -lsE -- '--autologin|-a[[:space:]]' \
    /etc/systemd/system/getty@*.service.d/*.conf \
    /etc/systemd/system/serial-getty@*.service.d/*.conf || true)"
for f in $AUTOLOGIN_FILES; do
    mv "$f" "/root/$(basename "$(dirname "$f")")-$(basename "$f").bak-$STAMP"
    echo "  removed console autologin: $f (takes effect after reboot)"
done
[ -n "$AUTOLOGIN_FILES" ] && systemctl daemon-reload

EMPTY_PW_USERS="$(awk -F: '$2=="" {print $1}' /etc/shadow)"
for u in $EMPTY_PW_USERS; do
    passwd -l "$u" >/dev/null
    echo "  locked account with EMPTY password: $u"
done

if [ "$LOCK_ROOT_PASSWORD" = yes ]; then
    passwd -l root >/dev/null
    echo "  locked root password (use sudo)"
fi

if [ "$SUDO_REQUIRE_PASSWORD" = yes ]; then
    for f in $SUDO_NOPASSWD_FILES; do
        backup "$f"
        # Move the backup out of /etc/sudoers.d; sudo would otherwise parse it.
        mv "$f.bak-$STAMP" "/root/$(basename "$f").bak-$STAMP"
        sed -i -E "s/^([[:space:]]*${SSH_USER}[[:space:]].*)NOPASSWD:[[:space:]]*/\1/" "$f"
        if ! visudo -cf "$f" >/dev/null; then
            cp -a "/root/$(basename "$f").bak-$STAMP" "$f"
            die "visudo rejected $f; original restored."
        fi
        echo "  removed NOPASSWD for $SSH_USER in $f"
    done
    echo "  sudo now asks for $SSH_USER's password"
fi
ok "Accounts reviewed."

# =================================================================================
# 9. Filesystem mounts and logging
# =================================================================================
task 9 "Hardening temporary filesystems and logging..."
FSTAB_CHANGED=no
fstab_add() {
    # fstab_add <mountpoint> <line>; skipped if fstab already has the mountpoint
    if ! awk -v m="$1" '$2==m {f=1} END {exit !f}' /etc/fstab; then
        [ "$FSTAB_CHANGED" = yes ] || backup /etc/fstab
        FSTAB_CHANGED=yes
        printf '# Added by pi-hardening\n%s\n' "$2" >> /etc/fstab
        echo "  fstab: $2"
    fi
}
fstab_add /dev/shm "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0"
[ "$TMPFS_TMP" = yes ] && fstab_add /tmp "tmpfs /tmp tmpfs defaults,nosuid,nodev,mode=1777,size=25% 0 0"
if [ "$FSTAB_CHANGED" = yes ]; then
    # A broken fstab drops a headless Pi into emergency mode, so verify first.
    if ! findmnt --verify --tab-file /etc/fstab >/dev/null 2>&1; then
        findmnt --verify --tab-file /etc/fstab || true
        cp -a "/etc/fstab.bak-$STAMP" /etc/fstab
        info "fstab verification failed; original restored and mount changes skipped."
    else
        systemctl daemon-reload
    fi
fi
mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null || true
[ "$TMPFS_TMP" = yes ] && echo "  /tmp moves to RAM after reboot"

# Keep logs across reboots (evidence of an intrusion should survive a reboot),
# but cap their size on the SD card.
mkdir -p "$(dirname "$JOURNALD_CONF")" /var/log/journal
cat > "$JOURNALD_CONF" <<'EOF'
# Managed by pi-hardening
[Journal]
Storage=persistent
SystemMaxUse=64M
SystemMaxFileSize=8M
RuntimeMaxUse=16M
EOF
systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
systemctl restart systemd-journald
journalctl --flush >/dev/null 2>&1 || true
ok "Mounts and logging configured (journal: persistent, max 64 MB)."

# =================================================================================
# 10. Cleanup
# =================================================================================
task 10 "Cleaning up..."
apt-get "${APT_OPTS[@]}" autoremove --purge
apt-get clean
ok "Cleanup complete."

# =================================================================================
# Summary
# =================================================================================
ok "==========================================================="
ok "            Raspberry Pi Hardening Complete"
ok "==========================================================="
echo "  - Packages updated (full-upgrade)."
echo "  - SSH: port $SSH_PORT, keys only, root login off, only '$SSH_USER' allowed."
echo "  - UFW: deny inbound except SSH (rate limited)${EXTRA_TCP_PORTS:+ and TCP $EXTRA_TCP_PORTS}."
echo "  - fail2ban: $INSTALL_FAIL2BAN"
echo "  - Kernel/network sysctl hardening: $SYSCTL_CONF"
echo "  - Automatic updates incl. Raspberry Pi repos (auto-reboot: $AUTO_REBOOT_UPDATES)."
echo "  - Bluetooth disabled: $DISABLE_BLUETOOTH   Avahi disabled: $DISABLE_AVAHI"
echo "  - Unused kernel modules blocked (USB storage too: $BLOCK_USB_STORAGE)."
echo "  - Console autologin removed: ${AUTOLOGIN_FILES:+yes}${AUTOLOGIN_FILES:-none found}   Empty-password accounts locked: ${EMPTY_PW_USERS:-none}"
echo "  - root password locked: $LOCK_ROOT_PASSWORD   sudo requires password: $SUDO_REQUIRE_PASSWORD"
echo "  - /dev/shm noexec; /tmp in RAM: $TMPFS_TMP; persistent journal capped at 64 MB."
echo "  - cloud-init disabled: $DISABLE_CLOUD_INIT"
echo "  - Log: $LOG_FILE   Backups: *.bak-$STAMP"
print_color yellow "Services listening on the network right now (anything unexpected? remove it):"
ss -H -tulpn 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\]|\[::ffff:127\.)/ {printf "    %-4s %-28s %s\n", $1, $5, $7}' || true
echo "    (UFW blocks inbound to anything not listed in the firewall rules above.)"
print_color red "BEFORE closing this session, open a NEW terminal and test:"
echo "    ssh -p $SSH_PORT $SSH_USER@<pi-address>"
print_color red "A REBOOT is required for all changes (firmware/kernel) to take effect."

if [ "$ASSUME_YES" != yes ]; then
    read -r -p "Reboot now? (y/n): " REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then ok "Rebooting..."; reboot; fi
fi
info "Reboot manually with 'sudo reboot' once you have verified SSH access."
exit 0
