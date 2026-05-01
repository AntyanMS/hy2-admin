#!/usr/bin/env python3
"""
Backup/restore helper for cascade rollout.
Default mode is full backup.
"""
from __future__ import annotations

import argparse
import shutil
import tarfile
from datetime import datetime
from pathlib import Path


BACKUP_ROOT = Path("/var/backups/hy2-admin")

SECTIONS = {
    "panel": [Path("/opt/hy2-admin")],
    "hysteria": [Path("/etc/hysteria/config.yaml"), Path("/etc/systemd/system/hysteria-server.service")],
    "nginx": [Path("/etc/nginx/sites-available"), Path("/etc/nginx/sites-enabled"), Path("/etc/nginx/nginx.conf")],
    "fail2ban": [Path("/etc/fail2ban/jail.d"), Path("/etc/fail2ban/filter.d")],
    "firewall": [Path("/etc/ufw")],
}


def selected_paths(include: list[str], full: bool) -> list[Path]:
    keys = list(SECTIONS.keys()) if full else include
    out: list[Path] = []
    for k in keys:
        out.extend(SECTIONS.get(k, []))
    return out


def do_backup(include: list[str], full: bool) -> int:
    ts = datetime.now().strftime("%Y%m%d-%H%M")
    name = f"backup-{ts}"
    work = BACKUP_ROOT / name
    work.mkdir(parents=True, exist_ok=True)

    for src in selected_paths(include, full):
        if not src.exists():
            continue
        dest = work / src.relative_to("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dest)

    archive = Path("/root") / f"hy2-backup-{ts}.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(work, arcname=work.name)
    print(f"backup_dir: {work}")
    print(f"archive: {archive}")
    return 0


def do_restore(archive: str, include: list[str], full: bool, dry_run: bool) -> int:
    arc = Path(archive)
    if not arc.exists():
        raise SystemExit(f"archive not found: {arc}")

    staging = BACKUP_ROOT / "restore-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)

    with tarfile.open(arc, "r:gz") as tf:
        tf.extractall(staging)

    children = [p for p in staging.iterdir() if p.is_dir()]
    if not children:
        raise SystemExit("invalid archive: no content dir")
    root = children[0]

    if dry_run:
        print(f"dry-run ok: {arc}")
        print(f"staging: {root}")
        return 0

    wanted = selected_paths(include, full)
    for dst in wanted:
        src = root / dst.relative_to("/")
        if not src.exists():
            continue
        if dst.is_dir() and dst.exists():
            shutil.rmtree(dst)
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    print(f"restore complete from: {arc}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="HY2 backup/restore helper")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p_b = sp.add_parser("backup")
    p_b.add_argument("--mode", choices=("full", "selective"), default="full")
    p_b.add_argument("--include", default="", help="Comma-list: panel,hysteria,nginx,fail2ban,firewall")

    p_r = sp.add_parser("restore")
    p_r.add_argument("--archive", required=True)
    p_r.add_argument("--mode", choices=("full", "selective"), default="full")
    p_r.add_argument("--include", default="", help="Comma-list for selective restore")
    p_r.add_argument("--dry-run", action="store_true")

    args = ap.parse_args()
    include = [x.strip() for x in args.include.split(",") if x.strip()]
    full = args.mode == "full"

    if args.cmd == "backup":
        return do_backup(include, full)
    return do_restore(args.archive, include, full, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
