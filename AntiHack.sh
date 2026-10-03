#!/usr/bin/env bash
# antihack.sh - best-effort Linux hardening baseline
# Test in VM first. Run as root. Not a guarantee.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi

LOG=/var/log/antihack.log
exec > >(tee -a "$LOG") 2>&1

. /etc/os-release
DISTRO_ID=${ID:-unknown}
DISTRO_LIKE=${ID_LIKE:-}
PM=""
if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
elif command -v yum >/dev/null; then PM=yum
elif command -v pacman >/dev/null; then PM=pacman
elif command -v zypper >/dev/null; then PM=zypper
elif command -v apk >/dev/null; then PM=apk
else echo "Unsupported package manager"; exit 1; fi

install_pkg() {
  for p in "$@"; do
    case $PM in
      apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "$p" || true ;;
      dnf) dnf install -y "$p" || true ;;
      yum) yum install -y "$p" || true ;;
      pacman) pacman -S --noconfirm --needed "$p" || true ;;
      zypper) zypper --non-interactive install "$p" || true ;;
      apk) apk add "$p" || true ;;
    esac
  done
}

enable_service() {
  local svc=$1
  systemctl enable --now "$svc" 2>/dev/null || service "$svc" start 2>/dev/null || true
}

# Update package lists
case $PM in
  apt) apt-get update -y ;;
  dnf) dnf makecache -y ;;
  yum) yum makecache -y ;;
  pacman) pacman -Sy --noconfirm ;;
  zypper) zypper --non-interactive refresh ;;
  apk) apk update ;;
esac

# Install baseline tools
install_pkg fail2ban auditd aide rkhunter lynis
case $PM in
  apt) install_pkg ufw unattended-upgrades ;;
  dnf|yum) install_pkg firewalld dnf-automatic ;;
  pacman) install_pkg ufw ;;
  zypper) install_pkg firewalld ;;
  apk) install_pkg ufw ;;
esac

# sysctl hardening
cat >/etc/sysctl.d/99-antihack.conf <<'EOF'
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
sysctl --system || true

# SSH hardening: back up, only apply if sshd exists
if [[ -f /etc/ssh/sshd_config ]]; then
  cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.antihack.bak.$(date +%F-%H%M%S)
  cat >/etc/ssh/sshd_config.d/99-antihack.conf <<'EOF'
Protocol 2
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
PermitEmptyPasswords no
EOF
  # Some distros don't include Include directive
  if ! grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config; then
    echo 'Include /etc/ssh/sshd_config.d/*.conf' >> /etc/ssh/sshd_config
  fi
  sshd -t && systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi

# Firewall
if command -v ufw >/dev/null; then
  ufw --force reset || true
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow ssh
  ufw --force enable || true
elif command -v firewall-cmd >/dev/null; then
  systemctl enable --now firewalld || true
  firewall-cmd --permanent --add-service=ssh || true
  firewall-cmd --set-default-zone=drop || true
  firewall-cmd --reload || true
fi

# Fail2ban
if [[ -f /etc/fail2ban/jail.conf ]]; then
  cat >/etc/fail2ban/jail.d/antihack.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
EOF
  enable_service fail2ban
fi

# Auditd
enable_service auditd || enable_service audit

# AIDE init if missing
if command -v aide >/dev/null && [[ ! -f /var/lib/aide/aide.db ]]; then
  aideinit -y -f 2>/dev/null || aide --init 2>/dev/null || true
  [[ -f /var/lib/aide/aide.db.new ]] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || true
fi

# Automatic updates
if [[ $PM == apt ]]; then
  dpkg-reconfigure -plow unattended-upgrades || true
elif [[ $PM == dnf || $PM == yum ]]; then
  systemctl enable --now dnf-automatic.timer 2>/dev/null || true
fi

# Password quality
if [[ -f /etc/security/pwquality.conf ]]; then
  cat >/etc/security/pwquality.conf <<'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
EOF
fi

# umask
if ! grep -q '^umask 027' /etc/profile; then
  echo 'umask 027' >> /etc/profile
fi

# Final checks
lynis audit system --quick || true
rkhunter --update || true
rkhunter --check --sk || true

echo "Hardening baseline applied. Review $LOG. REBOOT recommended."
