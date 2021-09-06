# Парсер .exe файлов

## Описание
Парсер .exe файлов. После обработки exe файла выдает заголовки, секции и таблицу импортов.

## Установка
```bash
git clone https://github.com/keshakostya/exe-parser.git
pip install .
```

## Запуск

Консольный режим
```bash
python -m pe_parser.cli file.exe
```

Помощь
```bash
python -m pe_parser -h
