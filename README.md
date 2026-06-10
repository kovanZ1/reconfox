<div align="center">

# 🦊 reconfox

**CLI/TUI инструмент разведки веб-сервисов для авторизованного пентеста**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#)
[![Tests](https://img.shields.io/badge/tests-136%20passing-brightgreen.svg)](#тестирование)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-46a2f1.svg)](https://github.com/astral-sh/ruff)

</div>

---

> ⚠️ **ЭТИЧЕСКОЕ ИСПОЛЬЗОВАНИЕ.**
> Этот инструмент предназначен ИСКЛЮЧИТЕЛЬНО для:
> - тестирования собственных систем,
> - авторизованного пентеста с письменным разрешением владельца,
> - обучения на тренировочных стендах (DVWA, HackTheBox, TryHackMe, Metasploitable),
> - участия в CTF.
>
> Несанкционированное использование может являться нарушением законодательства РФ
> (ст. 272, 273, 274 УК РФ). Автор не несёт ответственности за неправомерное применение.

---

## Что делает reconfox

Запускаешь одной командой — получаешь полный отчёт о цели:

```
                    ┌─────────────┐
                    │   Resolver  │  URL → IP, ASN, ISP, Geolocation
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              ▼                          ▼
       ┌────────────┐            ┌────────────┐
       │    nmap    │            │    ffuf    │   параллельно
       │ (порты +   │            │ (директо-  │
       │  сервисы)  │            │   рии)     │
       └─────┬──────┘            └─────┬──────┘
             │                          │
             ▼                          │
   ┌──────────────────┐                 │
   │  Exploit Finder  │                 │
   │  searchsploit /  │                 │
   │  msfrpcd (опц.)  │                 │
   └─────────┬────────┘                 │
             │                          │
             └──────────┬───────────────┘
                        ▼
                ┌───────────────┐
                │  HTML / MD    │
                │    отчёт      │
                └───────────────┘
```

### Возможности

| Модуль | Что делает |
|--------|-----------|
| **Resolver** | URL → IP, ASN, ISP, страна, город, координаты (ip-api.com) |
| **Nmap** | Сканирование портов с 3 профилями: quick / full / stealth |
| **ffuf** | Поиск веб-директорий по wordlist |
| **searchsploit** | Поиск известных эксплоитов по версии сервиса |
| **Metasploit RPC** | Read-only поиск модулей Metasploit (опционально) |
| **Reporting** | HTML с тёмной темой + Markdown отчёт |
| **TUI** | Полноценный Textual интерфейс с live-прогрессом |
| **CLI** | Headless режим для CI/CD и скриптов |

---

## Установка

### Требования
- Python 3.11+
- Kali Linux или другой Linux с предустановленными `nmap` и `ffuf`
- Опционально: `metasploit-framework` с запущенным `msfrpcd`

### Установка из исходников

```bash
git clone https://github.com/kovanZ1/reconfox.git
cd reconfox
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

С опциональной поддержкой Metasploit RPC:

```bash
pip install -e ".[msf]"
```

### Установка инструментов в Kali

```bash
sudo apt update
sudo apt install nmap ffuf seclists exploitdb
# для Metasploit интеграции:
sudo apt install metasploit-framework
```

---

## Использование

### Интерактивный TUI (по умолчанию)

```bash
reconfox
```

Откроется Textual-интерфейс:
- введи URL цели
- выбери режим
- (опц.) включи Metasploit
- жми Run или клавишу `R`

### Headless CLI

```bash
# Быстрый скан с MD отчётом
reconfox scan https://example.com -o ./reports --no-tui

# Полный скан с HTML отчётом
reconfox scan https://example.com -m full -f html -o ./reports --no-tui

# Stealth + оба формата + Metasploit
reconfox scan https://example.com -m stealth -f both --metasploit --no-tui

# Кастомный wordlist
reconfox scan https://target.local \
    --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt \
    -o ./reports --no-tui
```

### Все опции

```
reconfox scan <URL> [OPTIONS]

  -m, --mode [quick|full|stealth]   Профиль скана (по умолчанию: quick)
  -o, --output PATH                 Папка для отчёта (по умолчанию: ./reports)
  -f, --format [md|html|both]       Формат отчёта (по умолчанию: md)
      --wordlist PATH               Wordlist для ffuf
      --nmap-binary PATH            Путь к nmap
      --ffuf-binary PATH            Путь к ffuf
      --metasploit                  Использовать msfrpcd вместо searchsploit
      --no-tui                      Headless режим
```

### Режимы сканирования

| Режим | Профиль nmap | Когда использовать |
|-------|--------------|--------------------|
| **quick** | `-T4 -F -sV` (топ-100 портов + версии) | Быстрая разведка, общая картина |
| **full** | `-T4 -p- -sV -sC` (все 65535 + NSE) | Полный аудит, детальный отчёт |
| **stealth** | `-T2 -sS -f -sV` (SYN + фрагменты) | Скрытное сканирование |

---

## Metasploit RPC интеграция

Для использования флага `--metasploit` нужен запущенный `msfrpcd`:

```bash
# В отдельном терминале — запусти RPC-демон
msfrpcd -P your_password -S -a 127.0.0.1
```

Настройки подключения через переменные окружения (см. `.env.example`):

```
MSF_RPC_HOST=127.0.0.1
MSF_RPC_PORT=55553
MSF_RPC_USER=msf
MSF_RPC_PASS=your_password
MSF_RPC_SSL=true
```

**Важно:** reconfox использует Metasploit только для **поиска** модулей по версии
сервиса. Эксплойты НЕ запускаются автоматически.

---

## Архитектура

```
src/reconfox/
├── models.py                  # Target, PortInfo, WebFinding, Vulnerability, ScanResult
├── cli.py                     # Click CLI
├── tui.py                     # Textual TUI
└── core/
    ├── resolver.py            # async DNS + ip-api.com
    ├── nmap_scanner.py        # async nmap wrapper + XML parser
    ├── ffuf_scanner.py        # async ffuf wrapper + JSON parser
    ├── exploit_finder.py      # searchsploit интеграция
    ├── metasploit_finder.py   # msfrpcd RPC клиент (read-only)
    └── orchestrator.py        # asyncio.gather всех сканеров
├── reporting/
    ├── markdown.py            # GitHub-flavored MD генератор
    ├── html.py                # Jinja2 шаблонизатор
    ├── writer.py              # ReportFormat + write_report
    └── templates/
        └── report.html.j2     # HTML шаблон с тёмной темой
```

### Принципы

- **Чистая архитектура:** каждый модуль изолирован, общается через модели и протоколы
- **Async-first:** все долгие операции через asyncio для параллелизма
- **Тестируемость:** каждый сканер — wrapper над CLI с DI через monkeypatch
- **Graceful degradation:** ошибка одного сканера не валит остальных
- **Безопасность:** defusedxml для парсинга nmap, autoescape в Jinja2

---

## Тестирование

```bash
pip install -e ".[dev]"
pytest -v
ruff check src tests
```

136 тестов, 100% pass:

| Модуль | Тесты |
|--------|-------|
| models | 38 |
| resolver | 8 |
| nmap_scanner | 13 |
| ffuf_scanner | 12 |
| orchestrator | 11 |
| reporting | 18 |
| cli | 10 |
| exploit_finder | 14 |
| metasploit_finder | 9 |
| tui | 3 |

---

## Дорожная карта

- [x] Этап 1 — Bootstrap проекта (pyproject, CI, MIT)
- [x] Этап 2 — Модели данных на pydantic v2
- [x] Этап 3 — Resolver (URL → IP/ASN/Geo)
- [x] Этап 4 — Async nmap wrapper
- [x] Этап 5 — Async ffuf wrapper
- [x] Этап 6 — Orchestrator (asyncio.gather)
- [x] Этап 7 — HTML/Markdown отчёт
- [x] Этап 8 — CLI на Click + Rich
- [x] Этап 9 — TUI на Textual
- [x] Этап 10 — Exploit Finder (searchsploit)
- [x] Этап 11 — Metasploit RPC интеграция
- [x] Этап 12 — Полная документация

### В планах (v0.2+)
- [ ] Поддержка IPv6
- [ ] WHOIS интеграция
- [ ] Cache результатов между запусками
- [ ] Plugin-система для пользовательских сканеров
- [ ] JSON отчёт для пайплайнов
- [ ] Поддержка нескольких целей за раз
- [ ] Docker образ

---

## Contributing

PR и issue приветствуются. Правила:

1. **Сначала тесты, потом код.** Любой PR без тестов — на доработку.
2. `ruff check src tests` должен проходить.
3. Описание PR на русском или английском.
4. Без breaking changes API без обсуждения.

---

## Похожие инструменты

- [reconftw](https://github.com/six2dez/reconftw) — расширенная разведка bash-скриптами
- [autorecon](https://github.com/Tib3rius/AutoRecon) — Python автоматизация nmap+nikto
- [Sn1per](https://github.com/1N3/Sn1per) — коммерческий пентест-сканер

reconfox — простой, прозрачный и расширяемый. Один файл — один сканер.

---

## Лицензия

[MIT](LICENSE) © 2026 Fedor Zuev (kovanZ1)

---

<div align="center">
<sub>Создано с ❤️ для авторизованного пентеста.</sub>
</div>
