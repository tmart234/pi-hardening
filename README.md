Sequence of events:
1) Apt update + upgrade
2) SSH Key Generation (optional)
3) Configure Firewall (UFW; only allow SSH and HTTPS)
4) Harden SSH Configuration (disable passowrd, etc)
5) Harden Kernel Parameters (sysctl)
6) Fail2Ban install + config for SSH
7) minimize running services
8) Enable Automatic Security updates

Depending on what you are trying to protect, you may also want:
- apparmor config
- systemd service hardening
- router vlan
