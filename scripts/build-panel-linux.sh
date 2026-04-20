#!/usr/bin/env bash
# Сборка однофайлового hy2-admin-panel для Linux x86_64 (amd64 через Docker).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

IMAGE="${BUILD_IMAGE:-python:3.12-slim-bookworm}"
OUT_NAME="${OUT_NAME:-hy2-admin-panel-linux-amd64}"

docker run --rm \
  -v "${ROOT}:/src" \
  -w /src \
  "${IMAGE}" \
  bash -lc '
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq binutils gcc libjpeg-dev zlib1g-dev >/dev/null
    pip install --no-cache-dir -q -r requirements.txt -r requirements-build.txt
    pyinstaller --noconfirm hy2-admin-panel.spec
    ls -la dist/
  '

install -m0755 "${ROOT}/dist/hy2-admin-panel" "${ROOT}/dist/${OUT_NAME}"
echo "Готово: ${ROOT}/dist/${OUT_NAME}"
