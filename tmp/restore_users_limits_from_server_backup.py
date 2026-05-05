#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
import tarfile
from datetime import datetime
from pathlib import Path


def parse_userpass(config_text: str) -> list[tuple[str, str]]:
    users: list[tuple[str, str]] = []
    in_auth = False
    in_userpass = False

    for line in config_text.splitlines():
        if re.match(r"^auth:\s*$", line):
            in_auth = True
            in_userpass = False
            continue
        if in_auth and re.match(r"^\S", line):
            break
        if not in_auth:
            continue
        if re.match(r"^\s{2}userpass:\s*$", line):
            in_userpass = True
            continue
        if not in_userpass:
            continue
        m = re.match(r"^\s{4}(.+?):\s*(.+?)\s*$", line)
        if m:
            users.append((m.group(1).strip(), m.group(2).strip()))
            continue
        if line.strip() == "":
            continue
        if re.match(r"^\s{2}\S", line):
            break
    return users


def replace_auth_block(current_config: str, users: list[tuple[str, str]]) -> str:
    auth_lines = ["auth:", "  type: userpass", "  userpass:"]
    for username, password in users:
        auth_lines.append(f"    {username}: {password}")
    auth_block = "\n".join(auth_lines) + "\n"

    if re.search(r"(?m)^auth:\s*$", current_config):
        return re.sub(
            r"(?ms)^auth:\s*\n(?:[ \t]+.*\n)*",
            auth_block + "\n",
            current_config,
            count=1,
        )
    if not current_config.endswith("\n"):
        current_config += "\n"
    return current_config + "\n" + auth_block


def backup_file(path: Path, stamp: str) -> None:
    if path.exists():
        shutil.copy2(path, path.with_name(f"{path.name}.bak-before-users-restore-{stamp}"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Restore only users and limits from server backup archive.")
    parser.add_argument("--archive", required=True, help="Path to migration backup .tar.gz on this server")
    args = parser.parse_args()

    archive_path = Path(args.archive)
    if not archive_path.is_file():
        raise SystemExit(f"Archive not found: {archive_path}")

    target_config = Path("/etc/hysteria/config.yaml")
    target_data_dir = Path("/opt/hy2-admin/data")
    restore_targets = {
        "user_state.json": target_data_dir / "user_state.json",
        "users_meta.json": target_data_dir / "users_meta.json",
        "user_notes.json": target_data_dir / "user_notes.json",
        "clients.json": target_data_dir / "clients.json",
    }

    config_member = None
    data_members: dict[str, tarfile.TarInfo] = {}

    with tarfile.open(archive_path, "r:gz") as tf:
        for member in tf.getmembers():
            name = member.name
            if name.endswith("/etc-hysteria/config.yaml"):
                config_member = member
            for filename in restore_targets:
                if name.endswith(f"/opt-hy2-admin/data/{filename}"):
                    data_members[filename] = member

        if config_member is None:
            raise SystemExit("Backup archive has no /etc-hysteria/config.yaml")

        extracted = tf.extractfile(config_member)
        if extracted is None:
            raise SystemExit("Failed to read backup config from archive")
        backup_config_text = extracted.read().decode("utf-8", errors="replace")

        users = parse_userpass(backup_config_text)
        if not users:
            raise SystemExit("No auth.userpass entries found in backup config")

        stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        backup_file(target_config, stamp)
        for path in restore_targets.values():
            backup_file(path, stamp)

        current_text = target_config.read_text(encoding="utf-8")
        new_text = replace_auth_block(current_text, users)
        target_config.write_text(new_text, encoding="utf-8")

        target_data_dir.mkdir(parents=True, exist_ok=True)
        restored_data_files = []
        for filename, target_path in restore_targets.items():
            member = data_members.get(filename)
            if member is None:
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            target_path.write_bytes(src.read())
            restored_data_files.append(filename)

    print(f"Restored users in config: {len(users)}")
    print("Restored data files: " + (", ".join(restored_data_files) if restored_data_files else "none"))
    print(f"Source archive: {archive_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

