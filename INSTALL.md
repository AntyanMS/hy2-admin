# Установка HY2 Admin

## Быстрый старт (как у [3x-ui](https://github.com/MHSanaei/3x-ui))

1. В корне репозитория создайте **релиз** GitHub и приложите артефакт `hy2-admin-panel-linux-amd64` (собирается скриптом `scripts/build-panel-linux.sh`, см. ниже). Имя файла должно совпадать с тем, что ожидает установщик.
2. При **форке** репозитория замените в `install_hy2_admin.sh` значение по умолчанию `HY2_GITHUB_REPO` и при необходимости URL в `install.sh`.
3. На сервере (Debian/Ubuntu, root):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_hy2_admin.sh)
```

Либо однострочник через короткий `install.sh`:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install.sh)
```

Переменные окружения перед запуском (опционально):

| Переменная | Назначение |
|------------|------------|
| `HY2_GITHUB_REPO` | `owner/repo` для загрузки бинарника из Releases (`.../latest/download/hy2-admin-panel-linux-amd64`) |
| `HY2_PANEL_BINARY_URL` | Полный URL бинарника (перекрывает авто-URL по репозиторию) |
| `HY2_PANEL_LOCAL_BINARY` | Путь к уже скачанному бинарнику на диске (офлайн-установка) |
| `USE_PANEL_BINARY=0` | Классический режим: venv + код из heredoc внутри `install_hy2_admin.sh` (без скачивания бинарника) |

## Сборка бинарника Linux amd64

На машине с Docker:

```bash
chmod +x scripts/build-panel-linux.sh
./scripts/build-panel-linux.sh
```

Результат: `dist/hy2-admin-panel-linux-amd64` — загрузите его в **Assets** релиза на GitHub.

## Документация по каскаду

См. [docs/CASCADE.md](docs/CASCADE.md).
