# reconfox

> CLI/TUI инструмент разведки веб-сервисов для авторизованного пентеста.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#)

**reconfox** объединяет в одной команде:

- Разрешение URL → IP, ASN, провайдер, геолокация, WHOIS
- Асинхронное сканирование портов (nmap)
- Параллельный поиск веб-директорий (ffuf)
- Поиск известных эксплоитов (searchsploit + опционально Metasploit RPC)
- Сборку красивого отчёта (HTML и Markdown)
- Полноценный TUI на Textual

> ⚠️ Этот инструмент предназначен ИСКЛЮЧИТЕЛЬНО для:
> - тестирования собственных систем,
> - авторизованного пентеста с письменным разрешением владельца,
> - обучения на тренировочных стендах (DVWA, HackTheBox, TryHackMe, Metasploitable),
> - участия в CTF.
>
> Несанкционированное использование может являться нарушением законодательства РФ
> (ст. 272, 273, 274 УК РФ). Автор не несёт ответственности за неправомерное применение.

---

## Статус

🟡 В активной разработке. См. [этапы](#дорожная-карта).

## Быстрый старт

```bash
git clone https://github.com/kovanZ1/reconfox.git
cd reconfox
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,msf]"

# Интерактивный TUI
reconfox

# CLI режим
reconfox scan https://example.com -o ./reports --format html
```

## Требования

- Python 3.11+
- Kali Linux (или Linux с установленными `nmap`, `ffuf`)
- Опционально: `metasploit-framework` с запущенным `msfrpcd` для интеграции

## Дорожная карта

- [x] Этап 1 — Bootstrap проекта
- [ ] Этап 2 — Модели данных
- [ ] Этап 3 — Resolver
- [ ] Этап 4 — Async nmap wrapper
- [ ] Этап 5 — Async ffuf wrapper
- [ ] Этап 6 — Orchestrator
- [ ] Этап 7 — HTML/Markdown отчёт
- [ ] Этап 8 — CLI
- [ ] Этап 9 — TUI
- [ ] Этап 10 — searchsploit
- [ ] Этап 11 — Metasploit RPC
- [ ] Этап 12 — Полная документация

## Лицензия

[MIT](LICENSE)
