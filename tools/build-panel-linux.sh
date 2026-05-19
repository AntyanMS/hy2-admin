#!/usr/bin/env bash
# Сборка hy2-admin-panel (linux/amd64) в dist/<version>/hy2-admin-panel
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-0.0.4}"
OUT_DIR="${ROOT}/dist/${VERSION}"
IMAGE="${HY2_PANEL_BUILD_IMAGE:-python:3.12-slim-bookworm}"

cd "${ROOT}"
mkdir -p "${OUT_DIR}"

echo "==> hy2-admin-panel v${VERSION} (linux/amd64) -> ${OUT_DIR}"

docker run --rm \
  -v "${ROOT}:/src:ro" \
  -v "${OUT_DIR}:/out" \
  -w /work \
  "${IMAGE}" \
  bash -ec '
    set -euo pipefail
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq binutils >/dev/null
    rm -rf /work && mkdir -p /work
    cp -a /src/app.py /src/launcher.py /src/hy2-admin-panel.spec /src/requirements.txt /src/requirements-build.txt /work/
    cp -a /src/templates /work/templates
    cd /work
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -q --upgrade pip
    pip install -q -r requirements-build.txt
    pyinstaller --noconfirm hy2-admin-panel.spec
    install -m 0755 dist/hy2-admin-panel /out/hy2-admin-panel
    ls -lh /out/hy2-admin-panel
  '

echo "Готово: ${OUT_DIR}/hy2-admin-panel"
