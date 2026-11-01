# pi-hardening

A single script that applies baseline security hardening to a **Raspberry Pi Zero 2 W**
running **Raspberry Pi OS Lite** (Bookworm or Trixie, 32- or 64-bit). It also runs on
other Pi models and older releases.

## Before you start

1. Flash Raspberry Pi OS Lite with Raspberry Pi Imager. Set a username, password,
   Wi-Fi and enable SSH.
2. On **your computer**, create a key and copy it to the Pi:
   ```sh
   ssh-keygen -t ed25519
   ssh-copy-id <user>@<pi-address>
   ```
   If you skip this, the script asks you to paste a public key, and stops if you don't.
   It never turns off password login for a user that has no key.

## Usage

```sh
curl -O https://raw.githubusercontent.com/tmart234/pi-hardening/main/harden_pi.sh
less harden_pi.sh            # read it first
chmod +x harden_pi.sh
sudo ./harden_pi.sh
```

All questions come first. After that the script runs unattended, which matters
because `apt full-upgrade` can take 20+ minutes on a Zero 2 W.

**Keep your SSH session open** and test a new login (`ssh -p <port> <user>@<pi>`)
before you log out or reboot.

### Non-interactive

Set any of these and pass `-y` to accept the defaults for the rest:

| Variable | Default | Meaning |
|---|---|---|
| `SSH_USER` | the `sudo` user | The only account allowed to log in over SSH |
| `SSH_PORT` | `22` | SSH port |
| `EXTRA_TCP_PORTS` | *(none)* | Extra inbound TCP ports, e.g. `"443 8080"` |
| `INSTALL_FAIL2BAN` | `yes` | Install and configure fail2ban |
| `DISABLE_BLUETOOTH` | `yes` | Turn off the Bluetooth radio (`dtoverlay=disable-bt`) |
| `DISABLE_AVAHI` | `no` | Turn off mDNS; `<hostname>.local` will stop working |
| `AUTO_REBOOT_UPDATES` | `no` | Let unattended-upgrades reboot at 04:00 for kernel updates |
| `SUDO_REQUIRE_PASSWORD` | `yes`* | Remove Pi OS's passwordless sudo |

\* Only offered if the user has a password set. Otherwise you could lose sudo access.

```sh
sudo SSH_PORT=2222 EXTRA_TCP_PORTS="443" ./harden_pi.sh -y
```

## What it does

1. **Updates** with `apt full-upgrade`, which Raspberry Pi recommends so that
   kernel and firmware updates get installed. New packages use
   `--no-install-recommends` to save RAM and SD space.
2. **SSH** settings go in `/etc/ssh/sshd_config.d/00-pi-hardening.conf`: keys only,
   no root login, `AllowUsers`, fewer auth attempts, a shorter login grace time, and
   no X11 forwarding. The script then checks the *effective* config with `sshd -T`
   and rolls back if any setting didn't apply.
3. **UFW**: inbound traffic is denied by default. SSH is allowed with rate limiting
   (`ufw limit`), plus any extra ports you list. mDNS and DHCP keep working.
4. **fail2ban** uses the systemd journal backend (Bookworm+ has no
   `/var/log/auth.log`) and bans through UFW, with ban times that grow for repeat
   offenders.
5. **sysctl**: blocks ICMP redirects and source routing, turns on SYN cookies,
   restricts `kptr`/`dmesg`, hardens BPF, `ptrace` and file protections, and
   disables suid core dumps.
6. **unattended-upgrades** also covers the Raspberry Pi repositories. On 32-bit
   Pi OS, every package comes from the `Raspbian` origin, so without this nothing
   gets updated automatically.
7. **Services**: turns off Bluetooth (`bluetooth`, `hciuart` and the radio itself)
   and, if you choose, Avahi. Wi-Fi is never touched because it's usually the Zero
   2 W's only network link.
8. **sudo**: optionally removes the default `NOPASSWD` rule. Every change is
   checked with `visudo -c`.
9. **Cleanup**: `autoremove --purge` and `apt-get clean`.

Output is logged to `/var/log/pi-hardening.log`. Every file the script changes is
backed up as `<file>.bak-<timestamp>`. You can run the script again safely, for
example to change the SSH port.

## Changes from v4

- SSH settings used to be appended to the end of `sshd_config`. sshd uses the
  *first* value it reads, and drop-ins like Imager/cloud-init's
  `50-cloud-init.conf` (`PasswordAuthentication yes`) are read first, so password
  login could stay **on** without any warning. The new drop-in and `sshd -T` check
  fix this.
- `UsePAM no` was removed. It breaks PAM account and session handling on Debian.
  The script also cleans up the block v4 left in `sshd_config`.
- The script no longer creates a key pair on the Pi and prints the private key.
  Keys should be generated on your own computer.
- fail2ban now actually starts on Bookworm (systemd backend) and watches the SSH
  port you chose.
- unattended-upgrades now runs without prompts and includes the Raspberry Pi repos.
- Avahi is no longer disabled by default, since headless Zero 2 W setups usually
  rely on `<hostname>.local`.
- HTTPS (443) is no longer opened unless you ask for it.

## Further hardening to consider

- **Physical access**: the serial console on the GPIO header gives a login prompt
  (`sudo raspi-config` → Interface → Serial). The SD card isn't encrypted, so anyone
  holding the card can read and change it. The Zero 2 W doesn't support Raspberry Pi
  secure boot (that's Pi 4/5/CM4 only).
- AppArmor (needs `apparmor=1 security=apparmor` in `cmdline.txt`)
- systemd service sandboxing (`systemd-analyze security`)
- Putting the Pi on its own VLAN or IoT network on your router
- If you use SSH from a phone or tablet, consider a hardware/FIDO2 key (`ed25519-sk`)
