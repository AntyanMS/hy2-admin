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
CASCADE_API_PORT="${CASCADE_API_PORT:-9443}"
CASCADE_DATA_DIR="/opt/hy2-admin/data/cascade"
CASCADE_TOOLS_DIR="/opt/hy2-admin/tools/cascade"
CASCADE_REGISTRATION_TOKEN=""
HY2_REPO_RAW_URL="${HY2_REPO_RAW_URL:-https://raw.githubusercontent.com/AntyanMS/hy2-admin/HEAD}"
SERVER_IP=""
FINAL_TLS_MODE=""
FINAL_TLS_CERT=""
FINAL_TLS_KEY=""
LE_ISSUE_NEEDED=0
CERTBOT_WEBROOT="/var/www/certbot"

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
  --cascade-node           Mark node as cascade/exit and print REGISTRATION_TOKEN for master panel
  --tls-mode <mode>        auto | acme | certbot (default: auto). В режиме certbot при отсутствии PEM сертификат Let's Encrypt выпускается автоматически (nginx + certbot webroot), нужен --email.
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
  local tls_lower cert_probe key_probe
  [[ -n "${DOMAIN}" ]] || die "--auto требует --domain"
  tls_lower="$(printf "%s" "${TLS_MODE}" | tr '[:upper:]' '[:lower:]')"
  cert_probe="${TLS_CERT_PATH:-/etc/letsencrypt/live/${DOMAIN}/fullchain.pem}"
  key_probe="${TLS_KEY_PATH:-/etc/letsencrypt/live/${DOMAIN}/privkey.pem}"

  if [[ "${TLS_MODE}" == "acme" || "${TLS_MODE}" == "auto" ]]; then
    [[ -n "${EMAIL}" ]] || die "--auto требует --email для acme/auto режима"
  fi
  if [[ "${tls_lower}" == "certbot" ]] && [[ ! -f "${cert_probe}" || ! -f "${key_probe}" ]]; then
    [[ -n "${EMAIL}" ]] || die "--tls-mode certbot: нужен --email для первичного выпуска Let's Encrypt (или положите PEM в ${cert_probe})."
  fi
  [[ -n "${HY2_PASS}" ]] || HY2_PASS="$(random_hex)"
}

install_packages() {
  log "Обновление пакетов..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y curl openssl ufw fail2ban nginx python3
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
    binary_path="${INSTALL_TMP_DIR}/hysteria"

    # Primary path: direct binary from GitHub Releases (more stable in poor networks).
    asset_name="$(detect_hysteria_asset)"
    asset_url="https://github.com/apernet/hysteria/releases/latest/download/${asset_name}"
    if download_with_resume "${asset_url}" "${binary_path}"; then
      install -m 0755 "${binary_path}" /usr/local/bin/hysteria
      if /usr/local/bin/hysteria version >/dev/null 2>&1; then
        return
      fi
      warn "Прямой бинарь скачан, но проверка версии не прошла."
    fi

    # Fallback path: official bootstrap script.
    warn "Прямая установка бинаря не удалась, пробую get.hy2.sh..."
    if download_with_resume "https://get.hy2.sh/" "${installer_path}"; then
      chmod +x "${installer_path}"
      if bash "${installer_path}" && command -v hysteria >/dev/null 2>&1; then
        return
      fi
    fi

    die "Не удалось установить Hysteria ни через бинарь, ни через get.hy2.sh."
  else
    log "Hysteria2 уже установлен."
  fi
}

prepare_site_stub() {
  mkdir -p "${MASQ_DIR}"
  install -d -m 0755 "${CERTBOT_WEBROOT}"
  cat > "${MASQ_DIR}/index.html" <<'HTML'
<!doctype html>
<html><head><meta charset="utf-8"><title>Site</title></head>
<body><h1>OK</h1></body></html>
HTML
}

configure_nginx_https_stub() {
  local cert key site_path ssl_dir
  site_path="/etc/nginx/sites-available/hy2-site.conf"
  cert="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  key="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

  if [[ ! -f "${cert}" || ! -f "${key}" ]]; then
    # Fallback for acme mode or missing LE certs: keep 443/tcp open with self-signed cert.
    ssl_dir="/etc/ssl/hy2-site"
    install -d -m 0755 "${ssl_dir}"
    cert="${ssl_dir}/fullchain.pem"
    key="${ssl_dir}/privkey.pem"
    if [[ ! -f "${cert}" || ! -f "${key}" ]]; then
      openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "${key}" \
        -out "${cert}" \
        -days 365 \
        -subj "/CN=${DOMAIN}" >/dev/null 2>&1
      chmod 0600 "${key}"
      chmod 0644 "${cert}"
    fi
    warn "Let's Encrypt сертификат не найден, nginx использует self-signed сертификат."
  fi

  cat > "${site_path}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root ${CERTBOT_WEBROOT};
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate ${cert};
    ssl_certificate_key ${key};

    root ${MASQ_DIR};
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

  rm -f /etc/nginx/sites-enabled/default
  ln -sfn "${site_path}" "/etc/nginx/sites-enabled/hy2-site.conf"
  nginx -t
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
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
  install -d -m 0755 /etc/hysteria
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

trafficStats:
  listen: 127.0.0.1:9999
  secret: $(random_hex)
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

trafficStats:
  listen: 127.0.0.1:9999
  secret: $(random_hex)
EOF
  fi
  chmod 644 "${CONFIG_PATH}"
}

choose_tls_mode() {
  local mode cert key
  LE_ISSUE_NEEDED=0
  mode="$(printf "%s" "${TLS_MODE}" | tr '[:upper:]' '[:lower:]')"
  cert="${TLS_CERT_PATH:-/etc/letsencrypt/live/${DOMAIN}/fullchain.pem}"
  key="${TLS_KEY_PATH:-/etc/letsencrypt/live/${DOMAIN}/privkey.pem}"

  case "${mode}" in
    auto)
      if [[ -f "${cert}" && -f "${key}" ]]; then
        FINAL_TLS_MODE="certbot"
        FINAL_TLS_CERT="${cert}"
        FINAL_TLS_KEY="${key}"
      else
        FINAL_TLS_MODE="acme"
      fi
      ;;
    acme)
      FINAL_TLS_MODE="acme"
      ;;
    certbot)
      FINAL_TLS_MODE="certbot"
      FINAL_TLS_CERT="${cert}"
      FINAL_TLS_KEY="${key}"
      if [[ ! -f "${cert}" || ! -f "${key}" ]]; then
        LE_ISSUE_NEEDED=1
        [[ -n "${EMAIL}" ]] || die "Для certbot без готового сертификата нужен email (--email)."
      fi
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
  elif [[ "${FINAL_TLS_MODE}" == "certbot" ]] && [[ "${LE_ISSUE_NEEDED}" -eq 0 ]]; then
    [[ -f "${FINAL_TLS_CERT}" ]] || die "Сертификат не найден: ${FINAL_TLS_CERT}"
    [[ -f "${FINAL_TLS_KEY}" ]] || die "Ключ не найден: ${FINAL_TLS_KEY}"
  fi
}

ensure_le_certificate_certbot_mode() {
  [[ "${FINAL_TLS_MODE}" == "certbot" ]] || return 0
  [[ "${LE_ISSUE_NEEDED}" -eq 1 ]] || return 0

  log "Выпуск Let's Encrypt (certbot http-01 / webroot) для ${DOMAIN}..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y certbot \
    || die "Не удалось установить пакет certbot."

  certbot certonly \
    --webroot \
    -w "${CERTBOT_WEBROOT}" \
    -d "${DOMAIN}" \
    -m "${EMAIL}" \
    --agree-tos \
    --no-eff-email \
    --non-interactive \
    || die "certbot не смог выпустить сертификат. Проверьте DNS A/AAAA для ${DOMAIN}, порты 80/tcp и nginx."

  [[ -f "${FINAL_TLS_CERT}" && -f "${FINAL_TLS_KEY}" ]] \
    || die "После certbot не найдены: ${FINAL_TLS_CERT} и ${FINAL_TLS_KEY}"
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
  rm -f /etc/fail2ban/jail.d/sshd-hard.local
  cat > /etc/fail2ban/jail.d/00-trusted-peers.local <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 77.220.143.56 188.127.249.241 185.239.49.36 94.159.40.2 185.239.48.216 193.124.56.13 193.124.59.183
EOF
  cat > /etc/fail2ban/jail.d/sshd-permanent-3.local <<'EOF'
[sshd]
enabled = true
maxretry = 3
findtime = 10m
bantime = -1
banaction = ufw
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
  if [[ "${CASCADE_NODE}" == "y" ]]; then
    ufw allow "${CASCADE_API_PORT}/tcp" >/dev/null 2>&1 || true
  fi
  ufw --force enable >/dev/null 2>&1 || true
}

start_service() {
  if [[ ! -f "/etc/systemd/system/${SERVICE_NAME}" ]]; then
    cat > "/etc/systemd/system/${SERVICE_NAME}" <<'EOF'
[Unit]
Description=Hysteria Server Service (config.yaml)
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  fi
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
}

installer_script_dir() {
  local src
  src="${BASH_SOURCE[0]:-$0}"
  if [[ -n "${src}" && "${src}" != "bash" && "${src}" != "/dev/fd/"* && -f "${src}" ]]; then
    cd "$(dirname "${src}")" && pwd
    return 0
  fi
  printf "%s" ""
}

install_cascade_tools() {
  local dest="${CASCADE_TOOLS_DIR}" src_dir repo_dir
  repo_dir="$(installer_script_dir)"
  mkdir -p "${dest}"
  if [[ -n "${repo_dir}" && -f "${repo_dir}/tools/cascade/remote_sync_service.py" ]]; then
    src_dir="${repo_dir}/tools/cascade"
    log "Копирование tools/cascade из репозитория (${src_dir})..."
    cp -a "${src_dir}/." "${dest}/"
  else
    log "Загрузка tools/cascade с GitHub (${HY2_REPO_RAW_URL})..."
    local base="${HY2_REPO_RAW_URL}/tools/cascade"
    local f
    for f in remote_sync_service.py cascade_common.py install_remote_sync_service.sh \
      register_remote_node.py register_remote_on_master.py master_sync_worker.py \
      install_master_sync_service.sh backup_restore.py README.md; do
      curl -4fsSL --connect-timeout 15 --max-time 120 "${base}/${f}" -o "${dest}/${f}"
    done
  fi
  chmod 0755 "${dest}"/*.sh 2>/dev/null || true
  [[ -f "${dest}/remote_sync_service.py" ]] || die "Не найден ${dest}/remote_sync_service.py"
}

install_cascade_remote_sync_service() {
  [[ -x "${CASCADE_TOOLS_DIR}/install_remote_sync_service.sh" ]] \
    || die "Нет ${CASCADE_TOOLS_DIR}/install_remote_sync_service.sh"
  bash "${CASCADE_TOOLS_DIR}/install_remote_sync_service.sh"
}

# Токен для master-панели: base64url(JSON), как tools/cascade/register_remote_node.py
generate_cascade_registration_token() {
  command -v python3 >/dev/null 2>&1 || die "Для каскадного узла нужен python3."
  CASCADE_HOST="${DOMAIN}" CASCADE_NAME="${DOMAIN}" CASCADE_API_PORT="${CASCADE_API_PORT}" \
    CASCADE_DATA_DIR="${CASCADE_DATA_DIR}" \
    CASCADE_HY2_PORT="443" \
    CASCADE_HY2_SERVER="${DOMAIN}" CASCADE_HY2_SNI="${DOMAIN}" \
    CASCADE_HOP_USERNAME="${HY2_USER}" CASCADE_HOP_PASSWORD="${HY2_PASS}" \
    python3 <<'PY'
import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from pathlib import Path

def sha256_hex(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

host = (os.environ.get("CASCADE_HOST") or "").strip()
if not host:
    raise SystemExit("CASCADE_HOST empty")
api_port = int(os.environ.get("CASCADE_API_PORT") or "9443")
name = (os.environ.get("CASCADE_NAME") or host).strip() or host
hy2_server = (os.environ.get("CASCADE_HY2_SERVER") or host).strip() or host
hy2_sni = (os.environ.get("CASCADE_HY2_SNI") or hy2_server).strip() or hy2_server
try:
    hy2_port = int(os.environ.get("CASCADE_HY2_PORT") or "443")
except ValueError:
    hy2_port = 443
hop_username = (os.environ.get("CASCADE_HOP_USERNAME") or "").strip()
hop_password = (os.environ.get("CASCADE_HOP_PASSWORD") or "").strip()

node_id = str(uuid.uuid4())
api_secret = secrets.token_urlsafe(48)
issued_at = int(time.time())
payload = {
    "node_id": node_id,
    "name": name,
    "host": host,
    "api_port": api_port,
    "api_secret": api_secret,
    "issued_at": issued_at,
    "role": "exit",
    "hy2_server": hy2_server,
    "hy2_sni": hy2_sni,
    "hy2_port": hy2_port,
    "hop_username": hop_username,
    "hop_password": hop_password,
}
payload["fingerprint"] = sha256_hex(f"{node_id}:{api_secret}:{host}:{api_port}")
token = b64url_encode(
    json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
)

data_dir = Path(os.environ.get("CASCADE_DATA_DIR", "/opt/hy2-admin/data/cascade"))
data_dir.mkdir(parents=True, exist_ok=True)
meta_path = data_dir / "remote_node.json"
meta_path.write_text(
    json.dumps(
        {
            "node_id": node_id,
            "name": name,
            "host": host,
            "api_port": api_port,
            "api_secret": api_secret,
            "fingerprint": payload["fingerprint"],
            "issued_at": issued_at,
            "hy2_server": hy2_server,
            "hy2_sni": hy2_sni,
            "hy2_port": hy2_port,
            "hop_username": hop_username,
            "hop_password": hop_password,
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
os.chmod(meta_path, 0o600)
print(token, end="")
PY
}

prepare_cascade_exit_node() {
  [[ "${CASCADE_NODE}" == "y" ]] || return 0
  log "Каскадный exit: tools, REGISTRATION_TOKEN, sync API на ${CASCADE_API_PORT}/tcp..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-yaml >/dev/null 2>&1 \
    || die "Для каскадного узла нужен пакет python3-yaml."
  install_cascade_tools
  CASCADE_REGISTRATION_TOKEN="$(generate_cascade_registration_token)"
  install_cascade_remote_sync_service
  local sync_state
  sync_state="$(systemctl is-active hy2-cascade-sync.service 2>/dev/null || true)"
  if [[ "${sync_state}" == "active" ]]; then
    log "hy2-cascade-sync.service: active"
  else
    warn "hy2-cascade-sync.service: ${sync_state:-unknown} — проверьте: journalctl -u hy2-cascade-sync.service -n 30"
  fi
  warn "С master (панель) должен быть доступен TCP ${CASCADE_API_PORT} на этот хост."
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
    [[ -n "${CASCADE_REGISTRATION_TOKEN}" ]] \
      || CASCADE_REGISTRATION_TOKEN="$(generate_cascade_registration_token)"
    echo
    echo "HOST ${DOMAIN}"
    echo "REGISTRATION_TOKEN (copy to master admin):"
    echo "${CASCADE_REGISTRATION_TOKEN}"
    echo "Cascade sync API: ${CASCADE_API_PORT}/tcp (hy2-cascade-sync.service)"
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
  configure_nginx_https_stub
  ensure_le_certificate_certbot_mode
  configure_nginx_https_stub
  sync_cert_for_hysteria
  write_hysteria_config
  prepare_cascade_exit_node
  install_renew_hook_if_possible
  configure_fail2ban
  configure_ufw
  start_service
  print_summary
}

main "$@"
