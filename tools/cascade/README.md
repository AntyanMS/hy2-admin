# Cascade tools

Набор утилит для первого этапа каскадной схемы.

## 0) На remote поднять sync API

При установке сервера с **`install_hysteria2.sh --cascade-node`** sync API поднимается автоматически.

Вручную (если узел ставили без `--cascade-node`):

```bash
sudo bash /opt/hy2-admin/tools/cascade/install_remote_sync_service.sh
```

На master поднять sync worker:

```bash
sudo bash /opt/hy2-admin/tools/cascade/install_master_sync_service.sh
```

## 1) На удаленном узле (exit-node) — REGISTRATION_TOKEN

Обычно токен уже напечатан установщиком (`--cascade-node`). Повторно или без установщика:

```bash
python3 /opt/hy2-admin/tools/cascade/register_remote_node.py --host <EXIT_HOST> --api-port 9443 --name exit-node-1
```

Скрипт выведет `REGISTRATION_TOKEN` (base64url, для поля в master-панели).

## 2) На master зарегистрировать узел

```bash
python3 /opt/hy2-admin/tools/cascade/register_remote_on_master.py --token "<TOKEN>" --through
```

Реестр сохраняется в:

`/opt/hy2-admin/data/cascade/remote_servers.json`

## 3) Backup/restore (по умолчанию полный)

Полный backup:

```bash
python3 /opt/hy2-admin/tools/cascade/backup_restore.py backup
```

Выборочный backup:

```bash
python3 /opt/hy2-admin/tools/cascade/backup_restore.py backup --mode selective --include panel,hysteria,nginx
```

Dry-run restore:

```bash
python3 /opt/hy2-admin/tools/cascade/backup_restore.py restore --archive /root/hy2-backup-20260430-1636.tar.gz --dry-run
```
