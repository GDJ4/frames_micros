# Набор ручных тестов (curl)

Все команды без «рваных» кавычек и обратных слэшей, чтобы не ловить `EOF` в zsh. Используем heredoc для тела запроса.

## Переменные окружения
```bash
export BASE_URL="http://localhost:8000/v1"
export EMAIL="test-$(date +%s)@example.com"
export PASSWORD="Password123!"
```

## 1. Регистрация пользователя — 201
```bash
curl -X POST "$BASE_URL/users/register" \
  -H "Content-Type: application/json" \
  -d @<(cat <<'JSON'
{
  "email": "'"$EMAIL"'",
  "password": "'"$PASSWORD"'",
  "name": "Test User"
}
JSON
)
```

## 2. Повторная регистрация — 409
```bash
curl -X POST "$BASE_URL/users/register" \
  -H "Content-Type: application/json" \
  -d @<(cat <<'JSON'
{
  "email": "'"$EMAIL"'",
  "password": "'"$PASSWORD"'",
  "name": "Test User"
}
JSON
)
```

## 3. Вход и получение JWT — 200
```bash
export TOKEN=$(curl -s -X POST "$BASE_URL/users/login" \
  -H "Content-Type: application/json" \
  -d @<(cat <<'JSON'
{
  "email": "'"$EMAIL"'",
  "password": "'"$PASSWORD"'"
}
JSON
)) && echo "TOKEN=$TOKEN"
```

## 4. Доступ без токена — 401
```bash
curl -i -X GET "$BASE_URL/users/me"
```

## 5. Профиль с токеном — 200
```bash
curl -X GET "$BASE_URL/users/me" \
  -H "Authorization: Bearer $TOKEN"
```

## 6. Создание заказа — 201
```bash
curl -X POST "$BASE_URL/orders" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d @<(cat <<'JSON'
{
  "items": [
    { "product": "brick", "quantity": 2, "price": 10 },
    { "product": "cement", "quantity": 1, "price": 25.5 }
  ]
}
JSON
)
```

## 7. Список своих заказов — 200
```bash
curl -X GET "$BASE_URL/orders" \
  -H "Authorization: Bearer $TOKEN"
```

## 8. Получение заказа по ID — 200
```bash
export ORDER_ID="<ORDER_ID>"  # подставьте из шага 6/7
curl -X GET "$BASE_URL/orders/$ORDER_ID" \
  -H "Authorization: Bearer $TOKEN"
```

## 9. Отмена своего заказа — 200
```bash
curl -X POST "$BASE_URL/orders/$ORDER_ID/cancel" \
  -H "Authorization: Bearer $TOKEN"
```

## 10. Попытка обновить чужой заказ (нужен второй пользователь) — 403
```bash
curl -X PATCH "$BASE_URL/orders/$ORDER_ID" \
  -H "Authorization: Bearer $OTHER_TOKEN" \
  -H "Content-Type: application/json" \
  -d @<(cat <<'JSON'
{ "status": "done" }
JSON
)
```
