# Dynamic Trust for Web Sessions

Репозиторий содержит прототип механизма динамической оценки доверия к веб-сессии и код для воспроизводимых экспериментов на `CSIC 2010`.

### Сервисный контур

- `auth_main.py` — сервис аутентификации и выдачи токенов.
- `risk_engine_main.py` — сервис оценки риска на основе поведенческой модели.
- `resource_main.py` — сервис доступа к защищённому ресурсу.
- `service_config.py` — общие настройки сервисов.
- `service_security.py` — общие функции для токенов и проверки привязки клиента.
- `smoke.py` — сквозная проверка взаимодействия сервисов.

### Поведенческая модель и данные

- `data/train_lstm.py` — обучение модели и вычисление метрик для атакующих сценариев.
- `data/csic_actions.py` — преобразование HTTP-запросов в токены действий.
- `data/csic_raw_parser.py` — разбор сырых файлов `CSIC 2010`.
- `data/output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm.csv` — нормализованные данные `CSIC 2010`.
- `data/lstm_risk_model.pt` — сохранённая обученная модель.

### Эксперименты

- `experiments/run_experiments.py` — запуск серии экспериментов по сетке параметров.
- `experiments/graph.py` — построение графиков по результатам.
- `experiments/heatmaps.py` — построение тепловых карт по результатам.


## Запуск сервисов

### 1. Сервис оценки риска

```powershell
uvicorn risk_engine_main:app --port 8002
```

### 2. Сервис аутентификации

```powershell
uvicorn auth_main:app --port 8001
```

### 3. Ресурсный сервис

```powershell
uvicorn resource_main:app --port 8003
```

### 4. Сквозная проверка

```powershell
python smoke.py
```

## Обучение модели

В репозитории есть код обучения и сохранённый чекпойнт. Если нужно переобучить модель или пересчитать метрики на атакующих сценариях, используется модуль:

```powershell
python -m data.train_lstm
```

## Запуск экспериментов

### Полный прогон

```powershell
python experiments/run_experiments.py
```

Результаты сохраняются в `experiments/results.csv`.

### Построение графиков

```powershell
python experiments/graph.py
```

### Построение тепловых карт

```powershell
python experiments/heatmaps.py
```

## Атакующие сценарии в экспериментах

В текущем экспериментальном контуре используются два сценария:

- `automated_bot_attack`
- `business_logic_bypass`

Оба сценария формируются поверх нормальных маршрутов `CSIC 2010` и проверяют поведенческий контур после аутентификации.
