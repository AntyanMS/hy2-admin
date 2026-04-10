#!/usr/bin/env bash
# Если при запуске видите «pipefail: invalid option» — файл в CRLF (часто после копирования с Windows).
# Исправление: sed -i 's/\r$//' install_hysteria2.sh
set -euo pipefail

# Hysteria2 one-shot installer based on your manual steps:
# 1) apt update/upgrade
# 2) install Hysteria2 via get.hy2.sh
# 3) create masquerade page in /var/www/masq
# 4) write /etc/hysteria/config.yaml
# 5) enable/start hysteria-server.service
# 6) configure ufw

MODE="interactive"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
ADMIN_USER="${ADMIN_USER:-Admin}"
ADMIN_PASS="${ADMIN_PASS:-}"
SSH_PORT="${SSH_PORT:-22}"
ENABLE_AUTOSTART="y"
START_NOW="y"
ENABLE_UFW="y"

SERVER_IP=""
CONFIG_PATH="/etc/hysteria/config.yaml"
MASQ_DIR="/var/www/masq"
SERVICE_NAME="hysteria-server.service"

usage() {
  cat <<'EOF'
Usage:
  ./install_hysteria2.sh --interactive
  ./install_hysteria2.sh --auto --domain example.com --email you@example.com [--admin-user Admin] [--admin-pass HEX] [--ssh-port 22]

Flags:
  --interactive          Interactive mode (default)
  --auto                 Non-interactive mode
  --domain <domain>      Domain for ACME and SNI
  --email <email>        Email for ACME
  --admin-user <user>    Initial Hysteria2 user (default: Admin)
  --admin-pass <pass>    Initial Hysteria2 password (hex recommended)
  --ssh-port <port>      SSH port for UFW rule (default: 22)
  --no-autostart         Do not enable service at boot
  --no-start             Do not start service after install
  --skip-ufw             Do not configure UFW
  -h, --help             Show this help

Env alternatives for --auto:
  DOMAIN, EMAIL, ADMIN_USER, ADMIN_PASS, SSH_PORT
EOF
}

log() { printf "[INFO] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*" >&2; }
die() { printf "[ERROR] %s\n" "$*" >&2; exit 1; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root."
  fi
}

detect_ip() {
  local ip=""
  ip="$(curl -4fsS https://ifconfig.me 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -z "${ip}" ]]; then
    ip="127.0.0.1"
  fi
  SERVER_IP="${ip}"
}

gen_pass() {
  openssl rand -hex 16
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --interactive)
        MODE="interactive"
        shift
        ;;
      --auto)
        MODE="auto"
        shift
        ;;
      --domain)
        DOMAIN="${2:-}"
        shift 2
        ;;
      --email)
        EMAIL="${2:-}"
        shift 2
        ;;
      --admin-user)
        ADMIN_USER="${2:-}"
        shift 2
        ;;
      --admin-pass)
        ADMIN_PASS="${2:-}"
        shift 2
        ;;
      --ssh-port)
        SSH_PORT="${2:-}"
        shift 2
        ;;
      --no-autostart)
        ENABLE_AUTOSTART="n"
        shift
        ;;
      --no-start)
        START_NOW="n"
        shift
        ;;
      --skip-ufw)
        ENABLE_UFW="n"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
  done
}

collect_interactive() {
  local in=""
  echo "=== Hysteria2 interactive installer ==="
  read -r -p "Domain (required for ACME): " in
  DOMAIN="${in}"
  [[ -n "${DOMAIN}" ]] || die "Domain is required."

  read -r -p "Email for ACME (required): " in
  EMAIL="${in}"
  [[ -n "${EMAIL}" ]] || die "Email is required."

  read -r -p "Admin username [Admin]: " in
  ADMIN_USER="${in:-Admin}"

  read -r -p "Admin password (leave empty to auto-generate): " in
  if [[ -n "${in}" ]]; then
    ADMIN_PASS="${in}"
  fi
  if [[ -z "${ADMIN_PASS}" ]]; then
    ADMIN_PASS="$(gen_pass)"
  fi

  read -r -p "SSH port for UFW [22]: " in
  SSH_PORT="${in:-22}"

  read -r -p "Enable service autostart? [Y/n]: " in
  in="${in:-Y}"
  [[ "${in}" =~ ^[Nn]$ ]] && ENABLE_AUTOSTART="n" || ENABLE_AUTOSTART="y"

  read -r -p "Start service now? [Y/n]: " in
  in="${in:-Y}"
  [[ "${in}" =~ ^[Nn]$ ]] && START_NOW="n" || START_NOW="y"

  read -r -p "Configure UFW rules? [Y/n]: " in
  in="${in:-Y}"
  [[ "${in}" =~ ^[Nn]$ ]] && ENABLE_UFW="n" || ENABLE_UFW="y"
}

validate_auto() {
  [[ -n "${DOMAIN}" ]] || die "--auto requires --domain (or DOMAIN env)."
  [[ -n "${EMAIL}" ]] || die "--auto requires --email (or EMAIL env)."
  [[ -n "${ADMIN_USER}" ]] || ADMIN_USER="Admin"
  if [[ -z "${ADMIN_PASS}" ]]; then
    ADMIN_PASS="$(gen_pass)"
  fi
}

install_system_updates() {
  log "Updating Ubuntu packages..."
  apt update
  apt upgrade -y
}

install_hysteria2() {
  log "Installing Hysteria2..."
  bash <(curl -fsSL https://get.hy2.sh/)
}

write_masquerade_site() {
  log "Preparing masquerade page..."
  mkdir -p "${MASQ_DIR}"
  tee "${MASQ_DIR}/index.html" >/dev/null <<'HTML'
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Please wait</title><style>body{background:#080808;height:100vh;margin:0;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:sans-serif}.dots{display:flex;gap:15px;margin-bottom:30px}.d{width:20px;height:20px;background:#fff;border-radius:50%;animation:b 1.4s infinite ease-in-out both}.d:nth-child(1){animation-delay:-0.32s}.d:nth-child(2){animation-delay:-0.16s}@keyframes b{0%,80%,100%{transform:scale(0);opacity:0.2}40%{transform:scale(1);opacity:1}}.t{color:#555;font-size:14px;letter-spacing:2px;font-weight:600}</style></head><body><div class="dots"><div class="d"></div><div class="d"></div><div class="d"></div></div><div class="t">RETRYING CONNECTION</div></body></html>
HTML
}

backup_config_if_exists() {
  if [[ -f "${CONFIG_PATH}" ]]; then
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    cp "${CONFIG_PATH}" "${CONFIG_PATH}.bak_${ts}"
    log "Existing config backed up: ${CONFIG_PATH}.bak_${ts}"
  fi
}

write_hysteria_config() {
  log "Writing ${CONFIG_PATH}..."
  tee "${CONFIG_PATH}" >/dev/null <<EOF
listen: 0.0.0.0:443

acme:
  type: http
  domains:
    - ${DOMAIN}
  email: ${EMAIL}

auth:
  type: userpass
  userpass:
    ${ADMIN_USER}: ${ADMIN_PASS}

masquerade:
  type: file
  file:
    dir: ${MASQ_DIR}
  listenHTTP: :80
  listenHTTPS: :443
  forceHTTPS: true
EOF
  chmod 644 "${CONFIG_PATH}"
}

setup_service() {
  log "Configuring service ${SERVICE_NAME}..."
  systemctl daemon-reload
  if [[ "${ENABLE_AUTOSTART}" == "y" ]]; then
    systemctl enable "${SERVICE_NAME}"
  fi
  if [[ "${START_NOW}" == "y" ]]; then
    systemctl restart "${SERVICE_NAME}"
  fi
}

setup_ufw() {
  if [[ "${ENABLE_UFW}" != "y" ]]; then
    log "UFW setup skipped."
    return
  fi
  if ! command -v ufw >/dev/null 2>&1; then
    log "Installing ufw..."
    apt update
    apt install -y ufw
  fi
  log "Applying UFW rules..."
  ufw allow "${SSH_PORT}/tcp"
  ufw allow 80/tcp
  ufw allow 443/udp
  ufw allow 443/tcp
  ufw --force enable
  ufw status verbose
}

print_result() {
  echo
  echo "========================================"
  echo "Hysteria2 installation completed"
  echo "Server IP:      ${SERVER_IP}"
  echo "Domain:         ${DOMAIN}"
  echo "SNI:            ${DOMAIN}"
  echo "Port:           443"
  echo "Username:       ${ADMIN_USER}"
  echo "Password:       ${ADMIN_PASS}"
  echo "Config:         ${CONFIG_PATH}"
  echo "Service:        ${SERVICE_NAME}"
  echo "Service status: $(systemctl is-active "${SERVICE_NAME}" || true)"
  echo "========================================"
  echo
  echo "Client URI template:"
  echo "hysteria2://${ADMIN_USER}:${ADMIN_PASS}@${DOMAIN}:443/?sni=${DOMAIN}#${ADMIN_USER}"
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

  install_system_updates
  install_hysteria2
  write_masquerade_site
  backup_config_if_exists
  write_hysteria_config
  setup_service
  setup_ufw
  print_result
}

main "$@"
