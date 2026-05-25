## Изменения

- Direct routing: блок **Custom** (сворачиваемая таблица), синхронизация **GitHub whitelist** из [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) (`whitelist.txt`), DNS → IP → правила `direct`, автообновление раз в сутки.
- Toast-уведомления, улучшения UI (каскад, трафик, резервное копирование), отложенный restart sing-box, исправление geoip-ru rule-set.
- Исходники панели на main; сборка: `tools/build-panel-linux.sh 0.0.5`.

**Внешние данные:** whitelist загружается с GitHub; благодарность автору [**hxehex**](https://github.com/hxehex) и репозиторию [russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) — см. [README](../README.md#синхронизация-whitelist-для-direct-routing-github).

## Установка панели

```bash
HY2_PANEL_RELEASE_TAG=v0.0.5 sudo ./install_hy2_admin.sh --auto ...
```
