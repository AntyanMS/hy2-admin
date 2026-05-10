#!/usr/bin/env bash
# Этап 3: установка/переключение gateway на sing-box поверх уже установленного Hysteria + панели.
#
# Запуск:
#   sudo bash install_singbox_gateway.sh
#   sudo bash install_singbox_gateway.sh --service-user example_hop_user
#
# Что делает:
# 1) Ставит sing-box (если нет бинаря).
# 2) Генерирует /etc/sing-box/config.json для inbound hysteria2 на :443.
# 3) Переключает hysteria на control-plane (127.0.0.1:24443).
# 4) Включает синхронизацию users из /etc/hysteria/config.yaml -> sing-box inbound.
set -euo pipefail

SERVICE_USER="${SERVICE_USER:-}"
SINGBOX_BIN="${SINGBOX_BIN:-/usr/local/bin/sing-box}"
SINGBOX_CONFIG_PATH="${SINGBOX_CONFIG_PATH:-/etc/sing-box/config.json}"
SINGBOX_LB_MODE="${SINGBOX_LB_MODE:-urltest}"
SINGBOX_GEOIP_RU_URL="${SINGBOX_GEOIP_RU_URL:-https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs}"
SKIP_BACKUP="${SKIP_BACKUP:-0}"

usage() {
  cat <<'EOF'
Usage:
  ./install_singbox_gateway.sh [--service-user <name>] [--skip-backup]

Flags:
  --service-user <name>   Служебный HY2 user для hop/каскада (по умолчанию автоопределение)
  --skip-backup           Не создавать backup перед переключением
  -h, --help              Показать help

Env:
  SERVICE_USER            То же, что --service-user (иначе автодетект из /etc/hysteria/config.yaml)
  SINGBOX_GEOIP_RU_URL    URL rule-set geoip-ru.srs
  SKIP_BACKUP=1           Не создавать backup
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERROR] Запустите скрипт от root." >&2
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-user)
        SERVICE_USER="${2:-}"
        shift 2
        ;;
      --skip-backup)
        SKIP_BACKUP=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "[ERROR] Неизвестный аргумент: $1" >&2
        exit 1
        ;;
    esac
  done
}

autodetect_service_user() {
  [[ -n "${SERVICE_USER}" ]] && return 0
  [[ -f /etc/hysteria/config.yaml ]] || {
    echo "[ERROR] /etc/hysteria/config.yaml не найден, а --service-user не задан." >&2
    exit 1
  }

  SERVICE_USER="$(
    python3 <<'PY'
from pathlib import Path
import yaml

p = Path("/etc/hysteria/config.yaml")
cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
up = (((cfg.get("auth") or {}).get("userpass")) or {})
if not isinstance(up, dict) or not up:
    raise SystemExit(1)

keys = [str(k).strip() for k in up.keys() if str(k).strip()]
if not keys:
    raise SystemExit(1)

# Предпочитаем "обычного" пользователя, а не служебного hop/cascade.
for k in keys:
    lk = k.lower()
    if "cascade" in lk or "hop" in lk:
        continue
    print(k)
    raise SystemExit(0)

print(keys[0])
PY
  )" || true

  if [[ -z "${SERVICE_USER}" ]]; then
    echo "[ERROR] Не удалось автоопределить service-user из auth.userpass в /etc/hysteria/config.yaml" >&2
    exit 1
  fi
  echo "[INFO] service-user автоопределён: ${SERVICE_USER}"
}

backup_state() {
  if [[ "${SKIP_BACKUP}" == "1" ]]; then
    echo "[backup] skipped"
    return
  fi
  local ts bd
  ts="$(date +%Y%m%d-%H%M%S)"
  bd="/opt/hy2-admin/backups/pre-singbox-${ts}"
  mkdir -p "${bd}"
  cp -a /etc/hysteria/config.yaml "${bd}/" 2>/dev/null || true
  cp -a /opt/hy2-admin/.env "${bd}/" 2>/dev/null || true
  if [[ -f /opt/hy2-admin/data/cascade/remote_servers.json ]]; then
    cp -a /opt/hy2-admin/data/cascade/remote_servers.json "${bd}/"
  fi
  echo "[backup] ${bd}"
}

install_singbox_if_missing() {
  local arch a rel ver url tmp tarball bin_path
  if [[ -x "${SINGBOX_BIN}" ]]; then
    "${SINGBOX_BIN}" version | sed -n '1,2p'
    return
  fi

  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) a=amd64 ;;
    aarch64|arm64) a=arm64 ;;
    *) echo "[ERROR] Unsupported arch: ${arch}" >&2; exit 1 ;;
  esac

  rel="$(curl -4fsSL --retry 10 --retry-all-errors --connect-timeout 20 --max-time 120 \
    https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")"
  ver="${rel#v}"
  url="https://github.com/SagerNet/sing-box/releases/download/${rel}/sing-box-${ver}-linux-${a}.tar.gz"

  tmp="/tmp/sing-box-install-$(date +%s)"
  tarball="${tmp}/sing-box.tgz"
  mkdir -p "${tmp}"
  curl -4fL --retry 8 --retry-all-errors --connect-timeout 20 --max-time 300 "${url}" -o "${tarball}"
  tar -xzf "${tarball}" -C "${tmp}"

  bin_path="${tmp}/sing-box-${ver}-linux-${a}/sing-box"
  if [[ ! -f "${bin_path}" ]]; then
    echo "[ERROR] sing-box binary not found in archive: ${bin_path}" >&2
    exit 1
  fi
  install -m 0755 "${bin_path}" "${SINGBOX_BIN}"
  "${SINGBOX_BIN}" version | sed -n '1,2p'
}

write_singbox_config() {
  install -d -m 0755 /etc/sing-box

  python3 <<PY
import json
from pathlib import Path
import yaml

SERVICE_USER = "${SERVICE_USER}"
SINGBOX_LB_MODE = "${SINGBOX_LB_MODE}"
GEOIP_RU_URL = "${SINGBOX_GEOIP_RU_URL}"
CFG_PATH = Path("${SINGBOX_CONFIG_PATH}")

hy = yaml.safe_load(Path("/etc/hysteria/config.yaml").read_text(encoding="utf-8")) or {}
users_map = (((hy.get("auth") or {}).get("userpass")) or {})
users = [{"name": str(k), "password": str(v)} for k, v in users_map.items()]

service_pass = str(users_map.get(SERVICE_USER, "")).strip()
if not service_pass:
    raise SystemExit(f"missing auth.userpass[{SERVICE_USER}] on gateway hysteria config")

dbp = Path("/opt/hy2-admin/data/cascade/remote_servers.json")
db = json.loads(dbp.read_text(encoding="utf-8")) if dbp.exists() else {"servers": []}
changed = False

cands = []
for s in db.get("servers") or []:
    if not isinstance(s, dict):
        continue
    if not s.get("enabled", True):
        continue
    if str(s.get("role", "")).strip().lower() != "exit":
        continue
    if not s.get("cascade_exit", False):
        continue
    host = str(s.get("hy2_server") or s.get("host") or "").strip()
    if not host:
        continue

    if str(s.get("hop_username") or "").strip() != SERVICE_USER:
        s["hop_username"] = SERVICE_USER
        changed = True
    if str(s.get("hop_password") or "").strip() != service_pass:
        s["hop_password"] = service_pass
        changed = True
    if str(s.get("hy2_server") or "").strip() != host:
        s["hy2_server"] = host
        changed = True
    s["hy2_port"] = int(s.get("hy2_port") or 443) or 443
    sni = str(s.get("hy2_sni") or "").strip() or host
    if str(s.get("hy2_sni") or "").strip() != sni:
        s["hy2_sni"] = sni
        changed = True
    if bool(s.get("hy2_insecure", False)):
        s["hy2_insecure"] = False
        changed = True
    cands.append(s)

db["singbox_lb_mode"] = SINGBOX_LB_MODE
if changed:
    dbp.parent.mkdir(parents=True, exist_ok=True)
    dbp.write_text(json.dumps(db, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

outbounds = [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
]

exit_tags = []
for s in cands:
    nid = "".join(ch for ch in str(s.get("node_id", "")) if ch.isalnum())[:16].lower() or "node"
    tag = f"cascade-hy2-{nid}"
    host = str(s.get("hy2_server") or s.get("host"))
    sni = str(s.get("hy2_sni") or host)
    port = int(s.get("hy2_port") or 443)
    usr = str(s.get("hop_username") or "").strip()
    pwd = str(s.get("hop_password") or "").strip()
    secret = f"{usr}:{pwd}" if usr else pwd

    outbounds.append(
        {
            "type": "hysteria2",
            "tag": tag,
            "server": host,
            "server_port": port,
            "password": secret,
            "tls": {"enabled": True, "server_name": sni, "insecure": bool(s.get("hy2_insecure", False))},
        }
    )
    exit_tags.append(tag)

selector_tag = "cascade-exit-auto"
if exit_tags:
    if SINGBOX_LB_MODE == "rr":
        outbounds.append(
            {
                "type": "selector",
                "tag": selector_tag,
                "outbounds": exit_tags,
                "default": exit_tags[0],
                "interrupt_exist_connections": False,
            }
        )
    else:
        outbounds.append(
            {
                "type": "urltest",
                "tag": selector_tag,
                "outbounds": exit_tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
                "tolerance": 50,
                "interrupt_exist_connections": False,
            }
        )

default_out = "direct" if not exit_tags else selector_tag
rules = [
    {"inbound": "in-hy2", "action": "sniff", "timeout": "1s"},
    {"domain_suffix": [".ru", ".su", ".xn--p1ai"], "outbound": "direct"},
    {"rule_set": ["geoip-ru"], "outbound": "direct"},
    {"outbound": default_out},
]

cfg = {
    "log": {"level": "info", "timestamp": True},
    "inbounds": [
        {
            "type": "hysteria2",
            "tag": "in-hy2",
            "listen": "::",
            "listen_port": 443,
            "users": users,
            "tls": {
                "enabled": True,
                "certificate_path": "/etc/hysteria/fullchain.pem",
                "key_path": "/etc/hysteria/privkey.pem",
            },
        }
    ],
    "outbounds": outbounds,
    "route": {
        "auto_detect_interface": True,
        "rules": rules,
        "rule_set": [
            {
                "tag": "geoip-ru",
                "type": "remote",
                "format": "binary",
                "url": GEOIP_RU_URL,
                "download_detour": "direct",
            }
        ],
    },
}

CFG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print("[sing-box] users=", len(users), " cascade exits=", len(exit_tags), " default=", default_out)
PY
}

write_units_and_sync() {
  cat >/etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  cat >/usr/local/bin/hy2-sync-users-to-singbox.py <<'EOF'
#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path
import yaml

HY_PATH = Path("/etc/hysteria/config.yaml")
SB_PATH = Path("/etc/sing-box/config.json")

hy_cfg = yaml.safe_load(HY_PATH.read_text(encoding="utf-8")) or {}
users_map = ((hy_cfg.get("auth") or {}).get("userpass") or {})
desired = [{"name": str(k), "password": str(v)} for k, v in users_map.items()]

sb_cfg = json.loads(SB_PATH.read_text(encoding="utf-8"))
changed = False
for ib in sb_cfg.get("inbounds") or []:
    if isinstance(ib, dict) and ib.get("tag") == "in-hy2":
        old = ib.get("users") or []
        if old != desired:
            ib["users"] = desired
            changed = True
        break

if changed:
    SB_PATH.write_text(json.dumps(sb_cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["/bin/systemctl", "try-restart", "sing-box.service"], check=False)
    print("updated sing-box users and restarted sing-box:", len(desired))
else:
    print("sing-box users unchanged, no restart")
EOF
  chmod 0755 /usr/local/bin/hy2-sync-users-to-singbox.py

  cat >/etc/systemd/system/hy2-sync-users-to-singbox.service <<'EOF'
[Unit]
Description=Sync Hysteria users into sing-box inbound
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/bin/hy2-sync-users-to-singbox.py
EOF

  cat >/etc/systemd/system/hy2-sync-users-to-singbox.path <<'EOF'
[Unit]
Description=Watch Hysteria config and sync users to sing-box

[Path]
PathChanged=/etc/hysteria/config.yaml
PathModified=/etc/hysteria/config.yaml
Unit=hy2-sync-users-to-singbox.service

[Install]
WantedBy=multi-user.target
EOF
}

switch_ports_and_restart() {
  systemctl daemon-reload

  echo "[switch] stopping hysteria on :443"
  systemctl stop hysteria-server.service || true

  echo "[switch] starting sing-box"
  systemctl enable sing-box.service
  systemctl restart sing-box.service
  sleep 2
  systemctl is-active sing-box.service

  echo "[switch] hysteria control-plane on 127.0.0.1:24443"
  python3 <<'PY'
from pathlib import Path
import yaml

p = Path("/etc/hysteria/config.yaml")
c = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
listen = str(c.get("listen", "")).strip()
if listen in {":443", "[::]:443", "0.0.0.0:443"}:
    c["listen"] = "127.0.0.1:24443"
    p.write_text(yaml.safe_dump(c, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print("hysteria listen -> 127.0.0.1:24443")
else:
    print("hysteria listen kept:", listen)
PY

  systemctl enable hysteria-server.service
  systemctl restart hysteria-server.service
  sleep 1
  systemctl is-active hysteria-server.service

  systemctl disable --now hy2-sync-users-to-singbox.timer >/dev/null 2>&1 || true
  systemctl enable --now hy2-sync-users-to-singbox.path
  systemctl start hy2-sync-users-to-singbox.service || true
}

print_checks() {
  echo "[listen:udp]"
  ss -lunp | rg ':443|:24443' || true
  echo "[listen:tcp]"
  ss -ltnp | rg ':443|:18080|:9999' || true
  echo "[done]"
}

main() {
  parse_args "$@"
  require_root
  autodetect_service_user
  backup_state
  install_singbox_if_missing
  write_singbox_config
  write_units_and_sync
  switch_ports_and_restart
  print_checks
}

main "$@"

