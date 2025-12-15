# Микросервисы на Go для «СистемаКонтроля»

Собран рабочий бэкенд на Go из трёх сервисов: API Gateway, сервис пользователей и сервис заказов. Реализованы JWT-аутентификация, проверка прав на уровне сервисов, логирование с `X-Request-ID`, ограничение частоты запросов на шлюзе и черновая поддержка доменных событий заказов.

## Что сделано
- Полный REST-набор в префиксе `/v1`: регистрация/логин, профиль, список пользователей (админ), статусы заказов и отмена.
- Единый формат ответов `{success, data|error}` с кодами ошибок.
- JWT HS256 без внешних библиотек, проверка ролей (`admin`) и прав на уровне сервисов (доступ только к своим заказам).
- Шлюз проксирует `/v1/users/**` и `/v1/orders/**`, валидирует JWT, добавляет `X-Request-ID`, ограничивает частоту (token bucket), прокидывает заголовки `X-User-*`.
- Наблюдаемость: структурные логи с `req_id`, health/status эндпоинты, маршрут `/v1/orders/events` (админ) с последними доменными событиями.
- Окружения dev/test/prod через env-файлы (`env/dev.env`, `env/test.env`, `env/prod.env`), переменные читаются в контейнерах.
- Минимальные unit-тесты: users (регистрация, логин, доступ), orders (создание заказа с моком users-сервиса).
- OpenAPI-спецификация `docs/openapi.yaml` для шлюза.

## Запуск
```bash
cd micro-task-template
# выбрать профиль окружения
docker compose --env-file env/dev.env up --build
```
Порты по умолчанию: gateway `8000`, users `9001`, orders `9002`.

## Переменные окружения (ключевые)
- `JWT_SECRET` — общий секрет для всех сервисов (обязателен).
- `INTERNAL_API_KEY` — секрет для внутренних запросов orders -> users.
- `USERS_SERVICE_URL`, `ORDERS_SERVICE_URL` — адреса сервисов для шлюза и orders.
- `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST` — параметры rate limit в gateway.
- `APP_ENV` — dev/test/prod (влияет на логи и health).

## Основные эндпоинты (через gateway)
- `POST /v1/users/register` — регистрация, возвращает токен.
- `POST /v1/users/login` — вход, выдаёт JWT.
- `GET /v1/users/me`, `PUT /v1/users/me` — профиль.
- `GET /v1/users` — список (только `admin`), фильтры `page, limit, email, name, role`.
- `GET /v1/orders` — список своих заказов, сортировки `sortBy=createdAt|total`, `sortDir`.
- `POST /v1/orders` — создать заказ (проверка существования пользователя через users-сервис).
- `GET /v1/orders/{id}`, `PATCH /v1/orders/{id}` (обновление статуса), `POST /v1/orders/{id}/cancel`.
- `GET /v1/orders/events` — последние доменные события (только `admin`).
- Health: `/status`, `/healthz`.

OpenAPI: `docs/openapi.yaml`.

## Тестирование
- Юнит-тесты:  
  - users: `GOCACHE=./.gocache go test ./...` внутри `service_users`  
  - orders: `GOCACHE=./.gocache go test ./...` внутри `service_orders`
- Минимальный ручной сценарий (через gateway):
  1. `POST /v1/users/register` с email/паролем → получить `token`.
  2. `GET /v1/users/me` с `Authorization: Bearer <token>` → профиль.
  3. `POST /v1/orders` c `items` → статус 201, `status=created`.
  4. `GET /v1/orders` → увидеть заказ.
  5. `PATCH /v1/orders/{id}` (админ) или `POST /v1/orders/{id}/cancel` (владелец) → обновлённый статус.

## Надёжность и безопасность
- Rate limit на шлюзе + прокидывание `X-Request-ID` во все сервисы.
- Валидация входных данных, контроль переходов статусов заказов, проверка ролей.
- Изоляция внутреннего API users через заголовок `X-Service-Key`.
- Безопасное хранение паролей: соль + SHA-256 (без внешних зависимостей).
# frames_micros
