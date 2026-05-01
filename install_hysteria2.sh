#!/usr/bin/env bash
set -euo pipefail

MODE="interactive"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
HY2_USER="${HY2_USER:-user1}"
HY2_PASS="${HY2_PASS:-}"
SSH_PORT="${SSH_PORT:-22}"
ENABLE_UFW="${ENABLE_UFW:-y}"
CASCADE_NODE="${CASCADE_NODE:-n}"
TLS_MODE="${TLS_MODE:-auto}"
TLS_CERT_PATH="${TLS_CERT_PATH:-}"
TLS_KEY_PATH="${TLS_KEY_PATH:-}"
INSTALL_TMP_DIR="${INSTALL_TMP_DIR:-/var/tmp/hy2-installer}"

SERVICE_NAME="hysteria-server.service"
CONFIG_PATH="/etc/hysteria/config.yaml"
MASQ_DIR="/var/www/hy2-site"
CASCADE_META="/etc/hysteria/cascade_node.json"
SERVER_IP=""
FINAL_TLS_MODE=""
FINAL_TLS_CERT=""
FINAL_TLS_KEY=""

log() { printf "[INFO] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*" >&2; }
die() { printf "[ERROR] %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./install_hysteria2.sh --interactive
  ./install_hysteria2.sh --auto --domain vpn.example.com --email admin@example.com [--hy2-user user1] [--hy2-pass pass] [--cascade-node]

Flags:
  --interactive            Interactive mode (default)
  --auto                   Non-interactive mode
  --domain <domain>        Domain for TLS/ACME
  --email <email>          Email for ACME
  --hy2-user <user>        First HY2 user (default: user1)
  --hy2-pass <pass>        First HY2 password (default: random)
  --ssh-port <port>        SSH port for UFW (default: 22)
  --cascade-node           Mark node as cascade/exit and print fingerprint
  --tls-mode <mode>        auto | acme | certbot (default: auto)
  --tls-cert <path>        Explicit cert path for tls-mode=certbot
  --tls-key <path>         Explicit key path for tls-mode=certbot
  --skip-ufw               Do not modify UFW
  -h, --help               Show help
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Запустите скрипт от root."
  fi
}

random_hex() {
  openssl rand -hex 16
}

detect_ip() {
  local ip
  ip="$(curl -4fsS https://ifconfig.me 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  SERVER_IP="${ip:-127.0.0.1}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --interactive) MODE="interactive"; shift ;;
      --auto) MODE="auto"; shift ;;
      --domain) DOMAIN="${2:-}"; shift 2 ;;
      --email) EMAIL="${2:-}"; shift 2 ;;
      --hy2-user) HY2_USER="${2:-}"; shift 2 ;;
      --hy2-pass) HY2_PASS="${2:-}"; shift 2 ;;
      --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
      --cascade-node) CASCADE_NODE="y"; shift ;;
      --tls-mode) TLS_MODE="${2:-}"; shift 2 ;;
      --tls-cert) TLS_CERT_PATH="${2:-}"; shift 2 ;;
      --tls-key) TLS_KEY_PATH="${2:-}"; shift 2 ;;
      --skip-ufw) ENABLE_UFW="n"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Неизвестный аргумент: $1" ;;
    esac
  done
}

collect_interactive() {
  local input
  echo "=== Установка Hysteria2 (server-only) ==="
  read -r -p "Домен (обязателен для TLS): " input
  DOMAIN="${input}"
  [[ -n "${DOMAIN}" ]] || die "Нужен домен."

  read -r -p "Email для Let's Encrypt: " input
  EMAIL="${input}"
  [[ -n "${EMAIL}" ]] || die "Нужен email."

  read -r -p "Первый HY2 пользователь [user1]: " input
  HY2_USER="${input:-user1}"

  read -r -p "Пароль для первого пользователя (Enter = random): " input
  HY2_PASS="${input:-${HY2_PASS}}"
  if [[ -z "${HY2_PASS}" ]]; then
    HY2_PASS="$(random_hex)"
  fi

  read -r -p "Порт SSH для UFW [22]: " input
  SSH_PORT="${input:-22}"

  read -r -p "Это каскадный (exit) сервер? [y/N]: " input
  if [[ "${input:-N}" =~ ^[Yy]$ ]]; then
    CASCADE_NODE="y"
  fi

  read -r -p "Настроить UFW? [Y/n]: " input
  if [[ "${input:-Y}" =~ ^[Nn]$ ]]; then
    ENABLE_UFW="n"
  else
    ENABLE_UFW="y"
  fi
}

validate_auto() {
  [[ -n "${DOMAIN}" ]] || die "--auto требует --domain"
  if [[ "${TLS_MODE}" == "acme" || "${TLS_MODE}" == "auto" ]]; then
    [[ -n "${EMAIL}" ]] || die "--auto требует --email для acme/auto режима"
  fi
  [[ -n "${HY2_PASS}" ]] || HY2_PASS="$(random_hex)"
}

install_packages() {
  log "Обновление пакетов..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y curl openssl ufw fail2ban
}

detect_hysteria_asset() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) echo "hysteria-linux-amd64" ;;
    aarch64|arm64) echo "hysteria-linux-arm64" ;;
    armv7l|armv7|armhf) echo "hysteria-linux-arm" ;;
    i386|i686) echo "hysteria-linux-386" ;;
    *)
      die "Неподдерживаемая архитектура для авто-установки Hysteria: ${arch}"
      ;;
  esac
}

download_with_resume() {
  local url="$1"
  local out="$2"
  local rc
  local -a resume_opt=()
  if [[ -s "${out}" ]]; then
    resume_opt=(--continue-at -)
  fi

  curl -fL \
    --retry 20 \
    --retry-all-errors \
    --retry-delay 2 \
    --connect-timeout 20 \
    --max-time 0 \
    "${resume_opt[@]}" \
    "${url}" \
    -o "${out}" || rc=$?

  if [[ "${rc:-0}" -eq 0 ]]; then
    return 0
  fi

  # curl 33: server doesn't support byte ranges for resume.
  if [[ "${rc:-0}" -eq 33 ]]; then
    warn "Источник не поддерживает resume, перезапускаю скачивание с нуля..."
    rm -f "${out}"
    curl -fL \
      --retry 20 \
      --retry-all-errors \
      --retry-delay 2 \
      --connect-timeout 20 \
      --max-time 0 \
      "${url}" \
      -o "${out}"
    return $?
  fi

  return "${rc:-1}"
}

install_hysteria() {
  if ! command -v hysteria >/dev/null 2>&1; then
    log "Установка Hysteria2..."
    local installer_path asset_name asset_url binary_path
    mkdir -p "${INSTALL_TMP_DIR}"
    installer_path="${INSTALL_TMP_DIR}/get.hy2.sh"

    # Primary path: official bootstrap script.
    if download_with_resume "https://get.hy2.sh/" "${installer_path}"; then
      chmod +x "${installer_path}"
      if bash "${installer_path}"; then
        if command -v hysteria >/dev/null 2>&1; then
          return
        fi
      fi
    fi

    warn "Установка через get.hy2.sh не удалась, пробую прямой бинарь из GitHub Releases..."
    asset_name="$(detect_hysteria_asset)"
    asset_url="https://github.com/apernet/hysteria/releases/latest/download/${asset_name}"
    binary_path="${INSTALL_TMP_DIR}/hysteria"
    download_with_resume "${asset_url}" "${binary_path}"
    install -m 0755 "${binary_path}" /usr/local/bin/hysteria

    if ! /usr/local/bin/hysteria version >/dev/null 2>&1; then
      die "Hysteria бинарь скачан, но проверка версии не прошла."
    fi
  else
    log "Hysteria2 уже установлен."
  fi
}

prepare_site_stub() {
  mkdir -p "${MASQ_DIR}"
  cat > "${MASQ_DIR}/index.html" <<'HTML'
<!doctype html>
<html><head><meta charset="utf-8"><title>Site</title></head>
<body><h1>OK</h1></body></html>
HTML
}

backup_old_config() {
  if [[ -f "${CONFIG_PATH}" ]]; then
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    cp -a "${CONFIG_PATH}" "${CONFIG_PATH}.bak_${ts}"
    log "Бэкап конфига: ${CONFIG_PATH}.bak_${ts}"
  fi
}

write_hysteria_config() {
  log "Запись ${CONFIG_PATH}..."
  if [[ "${FINAL_TLS_MODE}" == "certbot" ]]; then
    cat > "${CONFIG_PATH}" <<EOF
listen: :443

tls:
  cert: /etc/hysteria/fullchain.pem
  key: /etc/hysteria/privkey.pem

auth:
  type: userpass
  userpass:
    ${HY2_USER}: ${HY2_PASS}
EOF
  else
    cat > "${CONFIG_PATH}" <<EOF
listen: :443

acme:
  type: http
  domains:
    - ${DOMAIN}
  email: ${EMAIL}

auth:
  type: userpass
  userpass:
    ${HY2_USER}: ${HY2_PASS}
EOF
  fi
  chmod 644 "${CONFIG_PATH}"
}

choose_tls_mode() {
  local mode cert key
  mode="$(printf "%s" "${TLS_MODE}" | tr '[:upper:]' '[:lower:]')"
  cert="${TLS_CERT_PATH:-/etc/letsencrypt/live/${DOMAIN}/fullchain.pem}"
  key="${TLS_KEY_PATH:-/etc/letsencrypt/live/${DOMAIN}/privkey.pem}"

  case "${mode}" in
    auto)
      if [[ -f "${cert}" && -f "${key}" ]]; then
        FINAL_TLS_MODE="certbot"
      else
        FINAL_TLS_MODE="acme"
      fi
      ;;
    acme|certbot)
      FINAL_TLS_MODE="${mode}"
      ;;
    *)
      die "Неверный --tls-mode: ${TLS_MODE}. Используйте auto|acme|certbot."
      ;;
  esac

  if [[ "${FINAL_TLS_MODE}" == "acme" ]]; then
    if systemctl is-active --quiet nginx; then
      die "nginx уже активен, acme http-01 через Hysteria конфликтует с 80/tcp. Используйте --tls-mode certbot."
    fi
    [[ -n "${EMAIL}" ]] || die "Для acme режима нужен email."
  else
    [[ -f "${cert}" ]] || die "Сертификат не найден: ${cert}"
    [[ -f "${key}" ]] || die "Ключ не найден: ${key}"
    FINAL_TLS_CERT="${cert}"
    FINAL_TLS_KEY="${key}"
  fi
}

sync_cert_for_hysteria() {
  if [[ "${FINAL_TLS_MODE}" != "certbot" ]]; then
    return
  fi
  local cert_owner cert_group
  cert_owner="root"
  cert_group="root"
  if id -u hysteria >/dev/null 2>&1; then
    cert_owner="hysteria"
    cert_group="hysteria"
  fi
  install -d -m 0755 /etc/hysteria
  install -o "${cert_owner}" -g "${cert_group}" -m 0644 "${FINAL_TLS_CERT}" /etc/hysteria/fullchain.pem
  install -o "${cert_owner}" -g "${cert_group}" -m 0600 "${FINAL_TLS_KEY}" /etc/hysteria/privkey.pem
}

install_renew_hook_if_possible() {
  if [[ "${FINAL_TLS_MODE}" != "certbot" ]]; then
    return
  fi
  local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
  local hook="${hook_dir}/hy2-sync-hysteria.sh"
  if [[ ! -d "/etc/letsencrypt" ]]; then
    return
  fi
  install -d -m 0755 "${hook_dir}"
  cat > "${hook}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DOMAIN="${RENEWED_DOMAINS%% *}"
if [[ -z "${DOMAIN}" ]]; then
  exit 0
fi
CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
if [[ ! -f "${CERT}" || ! -f "${KEY}" ]]; then
  exit 0
fi
if id -u hysteria >/dev/null 2>&1; then
  install -o hysteria -g hysteria -m 0644 "${CERT}" /etc/hysteria/fullchain.pem
  install -o hysteria -g hysteria -m 0600 "${KEY}" /etc/hysteria/privkey.pem
else
  install -o root -g root -m 0644 "${CERT}" /etc/hysteria/fullchain.pem
  install -o root -g root -m 0600 "${KEY}" /etc/hysteria/privkey.pem
fi
systemctl restart hysteria-server.service || true
EOF
  chmod 0755 "${hook}"
}

configure_fail2ban() {
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

configure_ufw() {
  if [[ "${ENABLE_UFW}" != "y" ]]; then
    log "UFW пропущен."
    return
  fi
  log "Применение UFW правил..."
  ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw allow 443/udp >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || true
}

start_service() {
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
}

write_cascade_fingerprint() {
  local fp token
  fp="$(printf '%s' "${DOMAIN}|${SERVER_IP}|${HY2_USER}" | sha256sum | awk '{print $1}')"
  token="$(openssl rand -hex 24)"
  cat > "${CASCADE_META}" <<EOF
{
  "role": "cascade_exit",
  "fingerprint": "${fp}",
  "registration_token": "${token}",
  "host": "${DOMAIN}",
  "port": 443
}
EOF
  chmod 600 "${CASCADE_META}"
  echo "${fp}|${token}"
}

print_summary() {
  local active enabled
  active="$(systemctl is-active "${SERVICE_NAME}" || true)"
  enabled="$(systemctl is-enabled "${SERVICE_NAME}" || true)"
  local uri_std uri_hiddify
  uri_std="hysteria2://${HY2_USER}:${HY2_PASS}@${DOMAIN}:443/?sni=${DOMAIN}&alpn=h3#${HY2_USER}"
  uri_hiddify="hysteria2://${HY2_PASS}@${DOMAIN}:443/?sni=${DOMAIN}&alpn=h3#${HY2_USER}"

  echo
  echo "========== Установка завершена =========="
  echo "Сервер: ${DOMAIN} (${SERVER_IP})"
  if [[ "${FINAL_TLS_MODE}" == "acme" ]]; then
    echo "TLS-режим: acme (http-01)"
    echo "Порты:    443/udp (HY2), 80/tcp (ACME challenge)"
  else
    echo "TLS-режим: certbot (внешний cert/key)"
    echo "Порты:    443/udp (HY2)"
  fi
  echo "Пользователь: ${HY2_USER}"
  echo "Пароль:       ${HY2_PASS}"
  echo
  echo "URI (standart): ${uri_std}"
  echo "URI (Hiddify):  ${uri_hiddify}"
  echo
  echo "Проверка сервиса:"
  echo "  systemctl status ${SERVICE_NAME}"
  echo "  systemctl is-active ${SERVICE_NAME}"
  echo "  systemctl is-enabled ${SERVICE_NAME}"
  echo "Текущее состояние: active=${active}, enabled=${enabled}"

  if [[ "${CASCADE_NODE}" == "y" ]]; then
    local pair fp token
    pair="$(write_cascade_fingerprint)"
    fp="${pair%%|*}"
    token="${pair##*|}"
    echo
    echo "Каскадный режим: ВКЛ"
    echo "Fingerprint: ${fp}"
    echo "Registration token: ${token}"
    echo "Файл: ${CASCADE_META}"
  fi
  echo "========================================="
}

main() {
  parse_args "$@"
  require_root
  detect_ip

  if [[ "${MODE}" == "interactive" ]]; then
    collect_interactive
  else
    validate_auto
  fi

  choose_tls_mode
  install_packages
  install_hysteria
  prepare_site_stub
  backup_old_config
  sync_cert_for_hysteria
  write_hysteria_config
  install_renew_hook_if_possible
  configure_fail2ban
  configure_ufw
  start_service
  print_summary
}

main "$@"
