# Набор ручных тестов (curl)

Команды готовы для вставки в терминал. Просто копируй и вставляй.

---

## 1. Регистрация пользователя — 201

```bash
curl -X POST "http://localhost:8000/v1/users/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"user1@test.com","password":"Password123!","name":"Test User"}'
```

---

## 2. Повторная регистрация (той же почты) — 409

```bash
curl -X POST "http://localhost:8000/v1/users/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"user1@test.com","password":"Password123!","name":"Test User"}'
```

---

## 3. Вход и получение JWT — 200

```bash
curl -X POST "http://localhost:8000/v1/users/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user1@test.com","password":"Password123!"}'
```

Сохрани значение из поля `data.token` для следующих запросов как `TOKEN`

---

## 4. Доступ без токена — 401

```bash
curl -X GET "http://localhost:8000/v1/users/me"
```

---

## 5. Получение профиля с токеном — 200

```bash
curl -X GET "http://localhost:8000/v1/users/me" \
  -H "Authorization: Bearer ВСТАВЬ_ТОКЕН_СЮДА"
```

---

## 6. Создание заказа — 201

```bash
curl -X POST "http://localhost:8000/v1/orders" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ВСТАВЬ_ТОКЕН_СЮДА" \
  -d '{"items":[{"product":"brick","quantity":2,"price":10},{"product":"cement","quantity":1,"price":25.5}]}'
```

Сохрани значение из поля `data.id` для следующих запросов как `ORDER_ID`

---

## 7. Получение списка своих заказов — 200

```bash
curl -X GET "http://localhost:8000/v1/orders" \
  -H "Authorization: Bearer ВСТАВЬ_ТОКЕН_СЮДА"
```

---

## 8. Получение заказа по ID — 200

```bash
curl -X GET "http://localhost:8000/v1/orders/ВСТАВЬ_ORDER_ID_СЮДА" \
  -H "Authorization: Bearer ВСТАВЬ_ТОКЕН_СЮДА"
```

---

## 9. Отмена своего заказа — 200

```bash
curl -X POST "http://localhost:8000/v1/orders/ВСТАВЬ_ORDER_ID_СЮДА/cancel" \
  -H "Authorization: Bearer ВСТАВЬ_ТОКЕН_СЮДА"
```

---

## 10. Регистрация второго пользователя для проверки прав — 201

```bash
curl -X POST "http://localhost:8000/v1/users/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"user2@test.com","password":"Password123!","name":"Other User"}'
```

---

## 11. Вход второго пользователя — 200

```bash
curl -X POST "http://localhost:8000/v1/users/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user2@test.com","password":"Password123!"}'
```

Сохрани токен как `OTHER_TOKEN`

---

## 12. Попытка обновить чужой заказ — 403

```bash
curl -X PATCH "http://localhost:8000/v1/orders/ВСТАВЬ_ORDER_ID_СЮДА" \
  -H "Authorization: Bearer ВСТАВЬ_OTHER_TOKEN_СЮДА" \
  -H "Content-Type: application/json" \
  -d '{"status":"done"}'
```
