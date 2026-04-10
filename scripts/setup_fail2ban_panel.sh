#!/usr/bin/env bash
set -euo pipefail
# One-shot: filter + jail for hy2-admin panel (run as root).

APP_PORT="${1:-8787}"
SERVICE_UNIT="${2:-hy2-admin.service}"

apt-get update -y
apt-get install -y fail2ban

mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d

cat > /etc/fail2ban/filter.d/hy2-admin-auth.conf <<'F2BFILTER'
[Definition]
failregex = ^.*<HOST>.*"(GET|POST|HEAD).*(HTTP/1\.[01]|HTTP/2(\.0)?)" 401 .*$
ignoreregex =
F2BFILTER

cat > /etc/fail2ban/jail.d/hy2-admin.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.0/8 ::1

[hy2-admin-auth]
enabled = true
port = ${APP_PORT}
protocol = tcp
backend = systemd
journalmatch = _SYSTEMD_UNIT=${SERVICE_UNIT}
filter = hy2-admin-auth
maxretry = 6
findtime = 10m
bantime = 2h
EOF

systemctl enable fail2ban
systemctl restart fail2ban
sleep 2
fail2ban-client reload || true
fail2ban-client status hy2-admin-auth || true
