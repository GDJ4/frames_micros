package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newOrdersTestServer(userServiceURL, apiKey, secret string, transport http.RoundTripper) http.Handler {
	cfg := config{
		Port:           "0",
		Env:            "test",
		JWTSecret:      secret,
		ServiceAPIKey:  apiKey,
		UsersService:   userServiceURL,
		HTTPTimeout:    2 * time.Second,
		DefaultPage:    1,
		DefaultPerPage: 10,
	}
	srv := &server{
		cfg:    cfg,
		store:  newOrderStore(),
		events: &eventStore{},
		logger: log.New(io.Discard, "", 0),
	}
	client := &http.Client{Timeout: cfg.HTTPTimeout}
	if transport != nil {
		client.Transport = transport
	}
	srv.client = client
	mux := http.NewServeMux()
	mux.Handle("/v1/orders/events", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleEvents))))
	mux.Handle("/v1/orders", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleOrders))))
	mux.Handle("/v1/orders/", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleOrderByID))))
	return srv.withRequestID(srv.withLogging(srv.withRecovery(mux)))
}

func issueTestToken(secret, userID string, roles []string) string {
	claims := tokenClaims{
		Subject: userID,
		Email:   "user@example.com",
		Roles:   roles,
		Exp:     time.Now().Add(time.Hour).Unix(),
		Issued:  time.Now().Unix(),
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := header + "." + payload
	return unsigned + "." + sign(unsigned, secret)
}

func TestCreateOrderSuccess(t *testing.T) {
	const userID = "user-1"
	const apiKey = "internal-key"
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Service-Key") != apiKey {
			return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
		}
		if req.URL.Path == "/v1/internal/users/"+userID {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString("{}"))}, nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})

	handler := newOrdersTestServer("http://service_users:9001", apiKey, "secret", rt)
	rr := perform(handler, http.MethodPost, "/v1/orders", map[string]interface{}{
		"items": []map[string]interface{}{
			{"product": "brick", "quantity": 2, "price": 10},
		},
	}, issueTestToken("secret", userID, []string{"user"}), t)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
	body := decodeRecorder(t, rr)
	if ok, _ := body["success"].(bool); !ok {
		t.Fatalf("success flag false")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func perform(handler http.Handler, method, path string, body interface{}, token string, t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func decodeRecorder(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var payload map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return payload
}
