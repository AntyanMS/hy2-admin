#!/usr/bin/env python3
"""Точка входа для однофайлового бинарника hy2-admin-panel (HTTP через Waitress или TLS через Hypercorn)."""
from __future__ import annotations

import asyncio
import os
import sys


def _ensure_cwd() -> None:
    os.chdir("/opt/hy2-admin")


def _run_waitress(app: object, host: str, port: int) -> None:
    from waitress import serve

    serve(app, host=host, port=port, threads=8)


def _run_hypercorn_tls(app: object, host: str, port: int, cert: str, key: str) -> None:
    from asgiref.wsgi import WsgiToAsgi
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    cfg = Config()
    cfg.bind = [f"{host}:{port}"]
    cfg.certfile = cert
    cfg.keyfile = key
    asgi = WsgiToAsgi(app)

    asyncio.run(serve(asgi, cfg))


def main() -> None:
    _ensure_cwd()
    host = os.environ.get("PANEL_BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("PANEL_BIND_PORT", "8787"))
    cert = (os.environ.get("PANEL_TLS_CERT") or "").strip()
    key = (os.environ.get("PANEL_TLS_KEY") or "").strip()

    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            sys.path.insert(0, meipass)
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, here)

    from app import app  # noqa: PLC0415

    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        _run_hypercorn_tls(app, host, port, cert, key)
    else:
        _run_waitress(app, host, port)


if __name__ == "__main__":
    main()
