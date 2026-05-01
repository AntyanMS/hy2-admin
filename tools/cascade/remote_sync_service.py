#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml


ENV_PATH = Path("/opt/hy2-admin/.env")
HY2_CONFIG = Path("/etc/hysteria/config.yaml")
HY2_SERVICE = "hysteria-server.service"
NODE_JSON = Path("/opt/hy2-admin/data/cascade/remote_node.json")
SYNC_STATUS = Path("/opt/hy2-admin/data/cascade/remote_last_apply.json")
BACKUP_DIR = Path("/opt/hy2-admin/backups/cascade-sync")


def load_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data) -> None:
    ensure_parent(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(str(tmp), str(path))


def load_cfg() -> dict:
    if not HY2_CONFIG.exists():
        raise RuntimeError(f"missing {HY2_CONFIG}")
    raw = HY2_CONFIG.read_text(encoding="utf-8")
    cfg = yaml.safe_load(raw) or {}
    if not isinstance(cfg, dict):
        raise RuntimeError("invalid hysteria config")
    cfg.setdefault("auth", {}).setdefault("userpass", {})
    return cfg


def write_cfg(cfg: dict) -> None:
    old_raw = HY2_CONFIG.read_text(encoding="utf-8")
    old_stat = HY2_CONFIG.stat()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUP_DIR / f"config-{ts}.yaml"
    backup.write_text(old_raw, encoding="utf-8")

    fd, tmp = tempfile.mkstemp(prefix="hy2-sync-", suffix=".yaml", dir=str(HY2_CONFIG.parent))
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        os.chmod(tmp, old_stat.st_mode)
        os.chown(tmp, old_stat.st_uid, old_stat.st_gid)
        os.replace(tmp, str(HY2_CONFIG))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

    subprocess.run(["systemctl", "restart", HY2_SERVICE], capture_output=True, text=True, timeout=60)


def verify_signature(body: bytes, signature_hex: str, secret: str) -> bool:
    if not signature_hex or not secret:
        return False
    expect = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, signature_hex.strip())


class Handler(BaseHTTPRequestHandler):
    server_version = "hy2-cascade-sync/0.1"

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/sync/full-users":
            self.send_error(404, "not found")
            return
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n)
        node = load_json(NODE_JSON, {})
        secret = str(node.get("api_secret", ""))
        sig = self.headers.get("X-Cascade-Signature", "")
        if not verify_signature(body, sig, secret):
            self.send_error(403, "bad signature")
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            snap = payload.get("snapshot") or {}
            auth_userpass = (snap.get("auth_userpass") or {})
            if not isinstance(auth_userpass, dict):
                raise ValueError("auth_userpass invalid")

            cfg = load_cfg()
            cfg.setdefault("auth", {}).setdefault("userpass", {})
            current_userpass = {str(k): str(v) for k, v in (cfg["auth"].get("userpass") or {}).items()}
            next_userpass = {str(k): str(v) for k, v in auth_userpass.items()}
            cfg_changed = current_userpass != next_userpass
            if cfg_changed:
                cfg["auth"]["userpass"] = next_userpass
                write_cfg(cfg)

            save_json(Path("/opt/hy2-admin/data/user_state.json"), snap.get("user_state") or {"disabled": {}})
            save_json(Path("/opt/hy2-admin/data/users_meta.json"), snap.get("user_meta") or {"users": {}})
            save_json(Path("/opt/hy2-admin/data/user_notes.json"), snap.get("user_notes") or {"users": {}})
            save_json(Path("/opt/hy2-admin/data/user_ip_state.json"), snap.get("user_ip_state") or {"users": {}})

            save_json(
                SYNC_STATUS,
                {
                    "ok": True,
                    "at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "reason": payload.get("reason", ""),
                    "source": payload.get("source", ""),
                    "users": len(auth_userpass),
                    "config_changed": cfg_changed,
                },
            )

            out = json.dumps({"ok": True, "users": len(auth_userpass)}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        except Exception as e:
            save_json(
                SYNC_STATUS,
                {
                    "ok": False,
                    "at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "error": str(e),
                },
            )
            self.send_error(500, str(e))

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return


def main() -> int:
    env = load_env(ENV_PATH)
    host = (env.get("CASCADE_SYNC_BIND_HOST") or "0.0.0.0").strip()
    port = int((env.get("CASCADE_SYNC_BIND_PORT") or "9443").strip())
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
