# Установка HY2 Admin

## Быстрый старт

На сервере (Debian/Ubuntu, `root`) выполните:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_hy2_admin.sh)
```

Либо:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install.sh)
```

## Полезно знать

- Скрипт сам скачает нужный бинарник панели и запустит `hy2-admin.service`.
- Для автоматического режима используйте аргумент `--auto`.
- Для интерактивного режима (по умолчанию) — `--interactive`.

Пример:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_hy2_admin.sh) --auto
```

## После установки

- Проверьте статус сервиса: `systemctl status hy2-admin.service`
- Откройте URL панели из вывода установщика.
