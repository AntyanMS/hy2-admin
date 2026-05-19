#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml


REMOTE_SERVERS = Path("/opt/hy2-admin/data/cascade/remote_servers.json")
STATE_FILE = Path("/opt/hy2-admin/data/cascade/master_sync_state.json")

HY2_CFG = Path("/etc/hysteria/config.yaml")
USER_STATE = Path("/opt/hy2-admin/data/user_state.json")
USER_META = Path("/opt/hy2-admin/data/users_meta.json")
USER_NOTES = Path("/opt/hy2-admin/data/user_notes.json")
USER_IP_STATE = Path("/opt/hy2-admin/data/user_ip_state.json")
ENV_PATH = Path("/opt/hy2-admin/.env")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


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


def load_auth_userpass() -> dict[str, str]:
    if not HY2_CFG.exists():
        return {}
    try:
        cfg = yaml.safe_load(HY2_CFG.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    auth = cfg.get("auth") if isinstance(cfg, dict) else {}
    up = auth.get("userpass") if isinstance(auth, dict) else {}
    if not isinstance(up, dict):
        return {}
    return {str(k): str(v) for k, v in up.items()}


def build_snapshot() -> dict[str, Any]:
    return {
        "auth_userpass": load_auth_userpass(),
        "user_state": load_json(USER_STATE, {"disabled": {}}),
        "user_meta": load_json(USER_META, {"users": {}}),
        "user_notes": load_json(USER_NOTES, {"users": {}}),
        "user_ip_state": load_json(USER_IP_STATE, {"users": {}}),
    }


def digest_snapshot(snapshot: dict[str, Any]) -> str:
    raw = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_remotes() -> list[dict[str, Any]]:
    db = load_json(REMOTE_SERVERS, {"servers": []})
    servers = db.get("servers") if isinstance(db, dict) else []
    out: list[dict[str, Any]] = []
    if not isinstance(servers, list):
        return out
    for s in servers:
        if not isinstance(s, dict):
            continue
        if not s.get("enabled", True):
            continue
        if str(s.get("role", "")).lower() != "exit":
            continue
        host = str(s.get("host", "")).strip()
        port = int(s.get("api_port", 0) or 0)
        sec = str(s.get("api_secret", "")).strip()
        if host and port > 0 and sec:
            out.append(s)
    return out


def send(remote: dict[str, Any], payload: dict[str, Any], timeout_sec: int) -> tuple[bool, str]:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    secret = str(remote["api_secret"])
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    req = Request(
        url=f"http://{remote['host']}:{int(remote['api_port'])}/sync/full-users",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Cascade-Signature": sig,
            "X-Cascade-Node": str(remote.get("node_id", "")),
        },
    )
    try:
        with urlopen(req, timeout=timeout_sec) as resp:
            code = int(getattr(resp, "status", 200))
            if 200 <= code < 300:
                return True, f"ok:{code}"
            return False, f"http:{code}"
    except URLError as e:
        return False, f"urlerror:{e}"
    except Exception as e:
        return False, f"error:{e}"


def main() -> int:
    env = load_env(ENV_PATH)
    if (env.get("CASCADE_MASTER_ENABLED") or "0").strip().lower() not in {"1", "true", "yes", "on"}:
        print("CASCADE_MASTER_ENABLED is off")
        return 0
    interval = int((env.get("CASCADE_SYNC_INTERVAL_SEC") or "5").strip() or "5")
    timeout_sec = int((env.get("CASCADE_SYNC_TIMEOUT_SEC") or "8").strip() or "8")
    interval = max(3, min(interval, 60))
    timeout_sec = max(3, min(timeout_sec, 30))

    while True:
        remotes = load_remotes()
        snapshot = build_snapshot()
        dgst = digest_snapshot(snapshot)
        state = load_json(STATE_FILE, {"last_digest": "", "rows": []})
        if dgst != state.get("last_digest"):
            payload = {
                "source": "gateway",
                "reason": "worker_auto_sync",
                "ts": int(time.time()),
                "snapshot": snapshot,
            }
            rows: list[dict[str, Any]] = []
            for r in remotes:
                ok, msg = send(r, payload, timeout_sec=timeout_sec)
                rows.append(
                    {
                        "node_id": r.get("node_id", ""),
                        "name": r.get("name", ""),
                        "host": r.get("host", ""),
                        "ok": ok,
                        "result": msg,
                        "at": datetime.now(timezone.utc).isoformat(),
                    }
                )
            save_json(
                STATE_FILE,
                {
                    "last_digest": dgst,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "rows": rows,
                },
            )
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
