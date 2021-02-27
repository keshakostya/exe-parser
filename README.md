# Парсер .exe файлов
## Описание
Парсер .exe файлов, написан на языке Python версии 3.7
## Установка
```bash
git clone repo
python setup.py
```

## Запуск

Консольный режим
```bash
python -m pe_parse.cli file.exe
# Вывод заголовков и разной другой информации
```

Помощь
```bash
python -m pe_parser -h
```

Запуск тестов
```bash
python -m pytest
```
## Автор
Аня Мартиросян, матмех