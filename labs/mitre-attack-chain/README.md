# Лаборатория: MITRE ATT&CK в действии

**Статус:** 🚧 В работе (начну 23.09.2026)

## Цель
Пройти цепочку из 5 техник MITRE ATT&CK на своих VM:
T1046 → T1110 → T1059 → T1053.003 → T1082

## Что будет в папке
- `README.md` — полный отчёт (заполню после прохождения)
- `screenshots/` — скриншоты каждого шага
- `logs/` — выдержки из `auth.log` и `syslog`

## Инструменты
- Nmap, Hydra, SSH, Cron
- Wazuh SIEM
- Ubuntu Server + Desktop

## Техники
| Шаг | Техника | Тактика |
|-----|---------|---------|
| 1 | T1046 | Discovery |
| 2 | T1110 | Credential Access |
| 3 | T1059 | Execution |
| 4 | T1053.003 | Persistence |
| 5 | T1082 | Discovery |