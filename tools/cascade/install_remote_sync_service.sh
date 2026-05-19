#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="hy2-cascade-sync.service"
SCRIPT="/opt/hy2-admin/tools/cascade/remote_sync_service.py"

if [[ ! -f "${SCRIPT}" ]]; then
  echo "missing ${SCRIPT}" >&2
  exit 1
fi

cat >/etc/systemd/system/${SERVICE_NAME} <<EOF
[Unit]
Description=HY2 Cascade Remote Sync API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${SCRIPT}
Restart=always
RestartSec=2
User=root
Group=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}
systemctl status ${SERVICE_NAME} --no-pager -n 20 || true
