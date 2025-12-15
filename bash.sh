#!/usr/bin/env bash
set -euo pipefail

API_URL="http://localhost:8000/v1"
EMAIL="user-$(date +%s)@example.com"
PASSWORD="Password123!"

echo "API_URL=$API_URL"
echo "EMAIL=$EMAIL"

echo "1) Register"
curl -s -X POST "$API_URL/users/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"'"$EMAIL"'","password":"'"$PASSWORD"'","name":"Test User"}'
echo -e "\n---"

echo "2) Login"
AUTH_TOKEN=$(curl -s -X POST "$API_URL/users/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"'"$EMAIL"'","password":"'"$PASSWORD"'"}' \
  | jq -r '.data.token')
echo "TOKEN=$AUTH_TOKEN"
echo "---"

echo "3) Profile"
curl -s -X GET "$API_URL/users/me" \
  -H "Authorization: Bearer $AUTH_TOKEN"
echo -e "\n---"

echo "4) Create order"
ORDER_JSON='{"items":[{"product":"brick","quantity":2,"price":10},{"product":"cement","quantity":1,"price":25.5}]}'

RESP=$(curl -s -w '\nHTTP=%{http_code}\n' -X POST "$API_URL/orders" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d "$ORDER_JSON")

echo "$RESP"
echo "---"

echo "5) Get order"
JSON_BODY=$(printf '%s' "$RESP" | sed -n '1p')
ORDER_ID=$(printf '%s' "$JSON_BODY" | jq -r 'try .data.id // empty')
if [ -z "$ORDER_ID" ]; then
  echo "order not created"
  exit 1
fi
curl -s -X GET "$API_URL/orders/$ORDER_ID" \
  -H "Authorization: Bearer $AUTH_TOKEN"
echo -e "\n---"
echo "Done."
