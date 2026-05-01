#!/usr/bin/env bash
set -euo pipefail

MODE="interactive"
APP_DOMAIN="${APP_DOMAIN:-}"
APP_EMAIL="${APP_EMAIL:-}"
PANEL_USER="${PANEL_USER:-admin}"
PANEL_PASS="${PANEL_PASS:-}"
PANEL_URL_PREFIX="${PANEL_URL_PREFIX:-}"
USE_RANDOM_CREDS="${USE_RANDOM_CREDS:-y}"
INTERNAL_PORT="${INTERNAL_PORT:-18080}"
INSTALL_DIR="/opt/hy2-admin"
SERVICE_NAME="hy2-admin.service"
NGINX_SITE_NAME="hy2-admin-panel"
NGINX_SITE_PATH="/etc/nginx/sites-available/${NGINX_SITE_NAME}"
BINARY_PATH="${INSTALL_DIR}/hy2-admin-panel"
PANEL_BINARY_URL="${HY2_PANEL_URL:-https://github.com/AntyanMS/hy2-admin/releases/latest/download/hy2-admin-panel-linux-amd64}"
PANEL_SESSION_SECRET=""
SERVER_HOST=""
USE_LETS_ENCRYPT="n"

log() { printf "[INFO] %s\n" "$*"; }
die() { printf "[ERROR] %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./install_hy2_admin.sh --interactive
  ./install_hy2_admin.sh --auto [--domain panel.example.com --email admin@example.com]

Flags:
  --interactive            Interactive mode (default)
  --auto                   Non-interactive mode
  --domain <domain>        Public domain for panel (optional)
  --email <email>          Email for Let's Encrypt (required when domain is set)
  --panel-user <user>      Manual panel username (with --manual-creds)
  --panel-pass <pass>      Manual panel password (with --manual-creds)
  --manual-creds           Use manual username/password
  --random-creds           Generate random username/password (default)
  --panel-url-prefix </x/panel>
                           Explicit panel URL prefix (default random)
  --binary-url <url>       Override panel binary URL
  -h, --help               Show help
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Запустите скрипт от root."
  fi
}

random_hex() {
  openssl rand -hex "${1:-16}"
}

detect_ipv4() {
  local ip
  ip="$(curl -4fsS https://ifconfig.me 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  [[ -n "${ip}" ]] || ip="127.0.0.1"
  printf "%s" "${ip}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --interactive) MODE="interactive"; shift ;;
      --auto) MODE="auto"; shift ;;
      --domain) APP_DOMAIN="${2:-}"; shift 2 ;;
      --email) APP_EMAIL="${2:-}"; shift 2 ;;
      --panel-user) PANEL_USER="${2:-}"; shift 2 ;;
      --panel-pass) PANEL_PASS="${2:-}"; shift 2 ;;
      --manual-creds) USE_RANDOM_CREDS="n"; shift ;;
      --random-creds) USE_RANDOM_CREDS="y"; shift ;;
      --panel-url-prefix) PANEL_URL_PREFIX="${2:-}"; shift 2 ;;
      --binary-url) PANEL_BINARY_URL="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Неизвестный аргумент: $1" ;;
    esac
  done
}

collect_interactive() {
  local input
  echo "=== Установка панели HY2 Admin (HTTPS-only) ==="
  read -r -p "Домен панели (Enter = использовать IPv4 сервера): " input
  APP_DOMAIN="${input}"

  if [[ -n "${APP_DOMAIN}" ]]; then
    USE_LETS_ENCRYPT="y"
    read -r -p "Email для SSL сертификата (Let's Encrypt): " input
    APP_EMAIL="${input}"
    [[ -n "${APP_EMAIL}" ]] || die "Email обязателен, если указан домен."
  fi

  read -r -p "Сгенерировать random user/pass для панели? [Y/n]: " input
  if [[ "${input:-Y}" =~ ^[Nn]$ ]]; then
    USE_RANDOM_CREDS="n"
    read -r -p "Panel user: " input
    PANEL_USER="${input}"
    [[ -n "${PANEL_USER}" ]] || die "Panel user обязателен."
    read -r -p "Panel pass: " input
    PANEL_PASS="${input}"
    [[ -n "${PANEL_PASS}" ]] || die "Panel pass обязателен."
  else
    USE_RANDOM_CREDS="y"
  fi

  read -r -p "Кастомный URL префикс панели (Enter = random): " input
  if [[ -n "${input}" ]]; then
    input="${input#/}"
    input="${input%/}"
    PANEL_URL_PREFIX="/${input}/panel"
  fi
}

validate_auto() {
  if [[ -n "${APP_DOMAIN}" ]]; then
    USE_LETS_ENCRYPT="y"
    [[ -n "${APP_EMAIL}" ]] || die "--auto: при указании домена нужен --email."
  fi
  if [[ "${USE_RANDOM_CREDS}" != "y" ]]; then
    [[ -n "${PANEL_USER}" ]] || die "--manual-creds: нужен --panel-user."
    [[ -n "${PANEL_PASS}" ]] || die "--manual-creds: нужен --panel-pass."
  fi
}

prepare_values() {
  if [[ -z "${APP_DOMAIN}" ]]; then
    SERVER_HOST="$(detect_ipv4)"
  else
    SERVER_HOST="${APP_DOMAIN}"
  fi

  if [[ "${USE_RANDOM_CREDS}" == "y" ]]; then
    PANEL_USER="admin"
    PANEL_PASS="$(random_hex 10)"
  fi

  if [[ -z "${PANEL_URL_PREFIX}" ]]; then
    PANEL_URL_PREFIX="/$(random_hex 16)/panel"
  fi
  PANEL_URL_PREFIX="${PANEL_URL_PREFIX%/}"
  [[ "${PANEL_URL_PREFIX}" == /* ]] || PANEL_URL_PREFIX="/${PANEL_URL_PREFIX}"

  PANEL_SESSION_SECRET="$(random_hex 32)"
}

install_packages() {
  log "Установка пакетов..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y curl openssl nginx fail2ban ufw
  if [[ "${USE_LETS_ENCRYPT}" == "y" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-nginx
  fi
}

download_binary() {
  log "Загрузка панели: ${PANEL_BINARY_URL}"
  mkdir -p "${INSTALL_DIR}"
  curl -fL "${PANEL_BINARY_URL}" -o "${BINARY_PATH}"
  chmod 0755 "${BINARY_PATH}"
}

write_env() {
  cat > "${INSTALL_DIR}/.env" <<EOF
SERVER_HOST=${SERVER_HOST}
SERVER_PORT=443
SERVER_SNI=${SERVER_HOST}
HY2_CONFIG_PATH=/etc/hysteria/config.yaml
HY2_SERVICE_NAME=hysteria-server.service
PANEL_BIND_HOST=127.0.0.1
PANEL_BIND_PORT=${INTERNAL_PORT}
PANEL_BASIC_USER=${PANEL_USER}
PANEL_BASIC_PASS=${PANEL_PASS}
PANEL_URL_PREFIX=${PANEL_URL_PREFIX}
PANEL_SESSION_SECRET=${PANEL_SESSION_SECRET}
PANEL_SESSION_COOKIE_SECURE=1
PANEL_NGINX_SITE_PATH=${NGINX_SITE_PATH}
SING_BOX_CONFIG_PATH=/etc/sing-box/config.json
EOF
  chmod 0600 "${INSTALL_DIR}/.env"
}

write_systemd_unit() {
  cat > "/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=HY2 Admin Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${BINARY_PATH}
Restart=always
RestartSec=2
User=root
Group=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
}

make_self_signed_cert() {
  local cert_dir="/etc/ssl/hy2-admin"
  mkdir -p "${cert_dir}"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${cert_dir}/panel.key" \
    -out "${cert_dir}/panel.crt" \
    -days 3650 \
    -subj "/CN=${SERVER_HOST}" >/dev/null 2>&1
  printf "%s|%s" "${cert_dir}/panel.crt" "${cert_dir}/panel.key"
}

write_nginx_site() {
  local cert_path="$1"
  local key_path="$2"
  cat > "${NGINX_SITE_PATH}" <<EOF
server {
  listen 80;
  listen [::]:80;
  server_name ${SERVER_HOST};
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name ${SERVER_HOST};

  ssl_certificate ${cert_path};
  ssl_certificate_key ${key_path};
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:10m;
  ssl_protocols TLSv1.2 TLSv1.3;

  location ${PANEL_URL_PREFIX}/ {
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Forwarded-Prefix ${PANEL_URL_PREFIX};
    proxy_pass http://127.0.0.1:${INTERNAL_PORT}${PANEL_URL_PREFIX}/;
  }

  location / {
    default_type text/plain;
    return 200 'ok';
  }
}
EOF

  ln -sfn "${NGINX_SITE_PATH}" "/etc/nginx/sites-enabled/${NGINX_SITE_NAME}"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
}

setup_tls_and_nginx() {
  local cert_path="" key_path=""
  if [[ "${USE_LETS_ENCRYPT}" == "y" ]]; then
    cat > "${NGINX_SITE_PATH}" <<EOF
server {
  listen 80;
  listen [::]:80;
  server_name ${SERVER_HOST};
  location / { return 200 "ok"; }
}
EOF
    ln -sfn "${NGINX_SITE_PATH}" "/etc/nginx/sites-enabled/${NGINX_SITE_NAME}"
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl restart nginx

    certbot --nginx -d "${SERVER_HOST}" -m "${APP_EMAIL}" --agree-tos --no-eff-email --non-interactive --redirect
    cert_path="/etc/letsencrypt/live/${SERVER_HOST}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${SERVER_HOST}/privkey.pem"
  else
    local cert_pair
    cert_pair="$(make_self_signed_cert)"
    cert_path="${cert_pair%%|*}"
    key_path="${cert_pair##*|}"
  fi

  write_nginx_site "${cert_path}" "${key_path}"
}

setup_fail2ban() {
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/sshd-hard.local <<'EOF'
[sshd]
enabled = true
maxretry = 5
findtime = 10m
bantime = 4h
EOF
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban || true
}

setup_ufw() {
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || true
}

print_summary() {
  local panel_url
  panel_url="https://${SERVER_HOST}${PANEL_URL_PREFIX}/"
  echo
  echo "========== Установка панели завершена =========="
  echo "URL панели: ${panel_url}"
  echo "Логин:      ${PANEL_USER}"
  echo "Пароль:     ${PANEL_PASS}"
  echo "Secret:     ${PANEL_SESSION_SECRET}"
  echo
  echo "Проверка:"
  echo "  systemctl status ${SERVICE_NAME}"
  echo "  systemctl is-active ${SERVICE_NAME}"
  echo "  systemctl is-enabled ${SERVICE_NAME}"
  echo "  systemctl status nginx"
  echo "==============================================="
}

main() {
  parse_args "$@"
  require_root

  if [[ "${MODE}" == "interactive" ]]; then
    collect_interactive
  else
    validate_auto
  fi
  prepare_values

  install_packages
  download_binary
  write_env
  write_systemd_unit
  setup_tls_and_nginx
  setup_fail2ban
  setup_ufw
  print_summary
}

main "$@"
