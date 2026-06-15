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


def _truthy(val) -> bool:
    if val is True or val == 1:
        return True
    if isinstance(val, str):
        return val.strip().lower() in {"1", "true", "yes", "on"}
    return False


def is_hybrid_sync(payload: dict, node: dict) -> bool:
    if _truthy(payload.get("hybrid")):
        return True
    if str(payload.get("sync_mode", "")).strip().lower() == "hybrid":
        return True
    return _truthy(node.get("hybrid"))


def merge_userpass(current: dict[str, str], master: dict[str, str]) -> dict[str, str]:
    merged = dict(current)
    merged.update({str(k): str(v) for k, v in master.items()})
    return merged


def merge_users_container(current: dict, master: dict, users_key: str = "users") -> dict:
    cur = current if isinstance(current, dict) else {}
    mst = master if isinstance(master, dict) else {}
    cur_users = cur.get(users_key) if isinstance(cur.get(users_key), dict) else {}
    mst_users = mst.get(users_key) if isinstance(mst.get(users_key), dict) else {}
    out = dict(cur)
    out[users_key] = {**dict(cur_users), **dict(mst_users)}
    return out


def merge_user_state(current: dict, master: dict, master_usernames: set[str]) -> dict:
    cur = current if isinstance(current, dict) else {}
    mst = master if isinstance(master, dict) else {}
    cur_dis = cur.get("disabled") if isinstance(cur.get("disabled"), dict) else {}
    mst_dis = mst.get("disabled") if isinstance(mst.get("disabled"), dict) else {}
    merged_dis = dict(cur_dis)
    for username in master_usernames:
        if username in mst_dis:
            merged_dis[username] = mst_dis[username]
        else:
            merged_dis.pop(username, None)
    out = dict(cur)
    out["disabled"] = merged_dis
    return out


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
            master_userpass = {str(k): str(v) for k, v in auth_userpass.items()}
            hybrid = is_hybrid_sync(payload, node)

            cfg = load_cfg()
            cfg.setdefault("auth", {}).setdefault("userpass", {})
            current_userpass = {str(k): str(v) for k, v in (cfg["auth"].get("userpass") or {}).items()}
            if hybrid:
                next_userpass = merge_userpass(current_userpass, master_userpass)
            else:
                next_userpass = master_userpass
            cfg_changed = current_userpass != next_userpass
            if cfg_changed:
                cfg["auth"]["userpass"] = next_userpass
                write_cfg(cfg)

            data_dir = Path("/opt/hy2-admin/data")
            master_users = set(master_userpass)
            if hybrid:
                user_state = merge_user_state(
                    load_json(data_dir / "user_state.json", {"disabled": {}}),
                    snap.get("user_state") or {"disabled": {}},
                    master_users,
                )
                user_meta = merge_users_container(
                    load_json(data_dir / "users_meta.json", {"users": {}}),
                    snap.get("user_meta") or {"users": {}},
                )
                user_notes = merge_users_container(
                    load_json(data_dir / "user_notes.json", {"users": {}}),
                    snap.get("user_notes") or {"users": {}},
                )
                user_ip_state = merge_users_container(
                    load_json(data_dir / "user_ip_state.json", {"users": {}}),
                    snap.get("user_ip_state") or {"users": {}},
                )
            else:
                user_state = snap.get("user_state") or {"disabled": {}}
                user_meta = snap.get("user_meta") or {"users": {}}
                user_notes = snap.get("user_notes") or {"users": {}}
                user_ip_state = snap.get("user_ip_state") or {"users": {}}

            save_json(data_dir / "user_state.json", user_state)
            save_json(data_dir / "users_meta.json", user_meta)
            save_json(data_dir / "user_notes.json", user_notes)
            save_json(data_dir / "user_ip_state.json", user_ip_state)

            save_json(
                SYNC_STATUS,
                {
                    "ok": True,
                    "at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "reason": payload.get("reason", ""),
                    "source": payload.get("source", ""),
                    "hybrid": hybrid,
                    "users": len(next_userpass),
                    "master_users": len(master_userpass),
                    "local_only_users": len(set(current_userpass) - master_users) if hybrid else 0,
                    "config_changed": cfg_changed,
                },
            )

            out = json.dumps(
                {
                    "ok": True,
                    "hybrid": hybrid,
                    "users": len(next_userpass),
                    "master_users": len(master_userpass),
                }
            ).encode("utf-8")
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
