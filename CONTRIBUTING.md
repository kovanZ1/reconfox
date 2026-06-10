# Contributing to reconfox

Спасибо за интерес к проекту! Любые PR и issue приветствуются.

## Workflow

1. Fork репозитория
2. Создай ветку для своей фичи: `git checkout -b feature/awesome`
3. **Сначала напиши тесты**, потом реализацию
4. Убедись что `pytest` и `ruff check src tests` зелёные
5. Коммить с понятным сообщением
6. Открой PR

## Локальная разработка

```bash
git clone https://github.com/kovanZ1/reconfox.git
cd reconfox
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,msf]"
pytest -v
```

## Стиль кода

- Python 3.11+ (используем `match`, `StrEnum`, `Self`)
- Type hints везде (проверка `mypy --strict` в планах)
- `ruff` как линтер и форматтер
- Async-first для I/O операций
- Pydantic v2 для моделей данных

## Тесты

- **Сначала тесты, потом код.** Это железное правило проекта.
- Каждый внешний инструмент (nmap, ffuf и т.д.) мокается через `monkeypatch`
- HTTP — через `respx`
- Async тесты — через `pytest-asyncio` (auto mode уже включён в `pyproject.toml`)

## Что приветствуется

- Новые сканеры (по принципу wrapper над CLI инструментом)
- Дополнительные форматы отчётов (JSON, SARIF)
- Улучшения TUI
- Локализация
- Тесты на больше edge cases

## Что НЕ приветствуется

- Функции которые автоматически запускают эксплойты
- Обход капч, rate-limits и других защит
- Что-либо способствующее несанкционированному доступу
- Нелегальные техники

reconfox — для авторизованного пентеста. PR противоречащие этому будут отклонены.

## Вопросы

Открывай issue с тегом `question`.
