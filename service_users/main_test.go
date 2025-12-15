package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testEnv struct {
	server  *server
	handler http.Handler
}

func newTestEnv() testEnv {
	cfg := config{
		Port:          "0",
		JWTSecret:     "test-secret",
		TokenTTL:      time.Hour,
		ServiceAPIKey: "internal",
		Env:           "test",
	}
	srv := &server{
		cfg:    cfg,
		store:  newUserStore(),
		logger: log.New(io.Discard, "", 0),
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/users/register", srv.withCORS(http.HandlerFunc(srv.handleRegister)))
	mux.Handle("/v1/users/login", srv.withCORS(http.HandlerFunc(srv.handleLogin)))
	mux.Handle("/v1/users/me", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleMe))))
	mux.Handle("/v1/users", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleListUsers))))
	mux.Handle("/v1/users/", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleUserByID))))
	root := srv.withRequestID(srv.withLogging(srv.withRecovery(mux)))
	return testEnv{server: srv, handler: root}
}

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

func decodeMap(t *testing.T, resp *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var payload map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return payload
}

func TestRegisterLoginFlow(t *testing.T) {
	env := newTestEnv()
	// Register
	resp := perform(env.handler, http.MethodPost, "/v1/users/register", map[string]interface{}{
		"email":    "test@example.com",
		"password": "secret123",
		"name":     "Tester",
	}, "", t)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.Code)
	}
	body := decodeMap(t, resp)
	if success, _ := body["success"].(bool); !success {
		t.Fatalf("success flag false")
	}

	// Duplicate register should fail
	resp = perform(env.handler, http.MethodPost, "/v1/users/register", map[string]interface{}{
		"email":    "test@example.com",
		"password": "secret123",
		"name":     "Tester",
	}, "", t)
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate, got %d", resp.Code)
	}

	// Login
	resp = perform(env.handler, http.MethodPost, "/v1/users/login", map[string]interface{}{
		"email":    "test@example.com",
		"password": "secret123",
	}, "", t)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 login, got %d", resp.Code)
	}
	body = decodeMap(t, resp)
	data := body["data"].(map[string]interface{})
	token := data["token"].(string)
	if token == "" {
		t.Fatalf("token not returned")
	}

	// Access profile with token
	resp = perform(env.handler, http.MethodGet, "/v1/users/me", nil, token, t)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for profile, got %d", resp.Code)
	}
}

func TestUnauthorizedAccess(t *testing.T) {
	env := newTestEnv()
	resp := perform(env.handler, http.MethodGet, "/v1/users/me", nil, "", t)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
}
