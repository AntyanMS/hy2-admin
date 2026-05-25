## Изменения

- **Суффиксы доменов → direct:** только зоны **России** (`.ru`, `.рф`, `.su`) — компактные чипы с встроенными SVG-флагами 24×16, зелёная рамка у включённых; в sing-box по-прежнему `.xn--p1ai` для `.рф`.
- Direct routing: блок **Custom** (сворачиваемая таблица), синхронизация **GitHub whitelist** из [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) (`whitelist.txt`), DNS → IP → правила `direct`, автообновление раз в сутки.
- Исправление падения панели при рендере суффиксов (конфликт ключа `items` в Jinja2).
- Установщик панели: по умолчанию `CASCADE_MASTER_ENABLED=1` (ручная синхронизация каскада с UI).

**Внешние данные:** whitelist загружается с GitHub; благодарность автору [**hxehex**](https://github.com/hxehex) и репозиторию [russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) — см. [README](../README.md#синхронизация-whitelist-для-direct-routing-github).

## Установка панели

```bash
HY2_PANEL_RELEASE_TAG=v0.0.6 sudo ./install_hy2_admin.sh --auto ...
```

Сборка из исходников: `bash tools/build-panel-linux.sh 0.0.6` (каталог `panel/` в репозитории).
