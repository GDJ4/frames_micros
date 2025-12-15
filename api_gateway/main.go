package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	Port             string
	Env              string
	UsersServiceURL  string
	OrdersServiceURL string
	JWTSecret        string
	RateLimitRPS     float64
	RateLimitBurst   int
}

type server struct {
	cfg         config
	logger      *log.Logger
	usersProxy  *httputil.ReverseProxy
	ordersProxy *httputil.ReverseProxy
	limiter     *rateLimiter
}

type ctxKey string

const (
	ctxRequestIDKey ctxKey = "request_id"
)

type apiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *apiError   `json:"error,omitempty"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type tokenClaims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Roles   []string `json:"roles"`
	Exp     int64    `json:"exp"`
	Issued  int64    `json:"iat"`
}

func main() {
	cfg := loadConfig()
	logger := log.New(os.Stdout, "api_gateway ", log.LstdFlags|log.LUTC)

	usersProxy := newProxy(cfg.UsersServiceURL, logger)
	ordersProxy := newProxy(cfg.OrdersServiceURL, logger)

	srv := &server{
		cfg:         cfg,
		logger:      logger,
		usersProxy:  usersProxy,
		ordersProxy: ordersProxy,
		limiter:     newRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst),
	}

	var handler http.Handler = http.HandlerFunc(srv.route)
	handler = srv.withCORS(handler)
	handler = srv.withRecovery(handler)
	handler = srv.withLogging(handler)
	root := srv.withRequestID(handler)

	addr := ":" + cfg.Port
	logger.Printf("starting api gateway on %s (env=%s)", addr, cfg.Env)
	server := &http.Server{
		Addr:         addr,
		Handler:      root,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("server failed: %v", err)
	}
}

func loadConfig() config {
	cfg := config{
		Port:             envDefault("PORT", "8000"),
		Env:              envDefault("APP_ENV", "dev"),
		UsersServiceURL:  envDefault("USERS_SERVICE_URL", "http://service_users:9001"),
		OrdersServiceURL: envDefault("ORDERS_SERVICE_URL", "http://service_orders:9002"),
		JWTSecret:        envDefault("JWT_SECRET", "local-dev-secret"),
		RateLimitRPS:     floatEnv("RATE_LIMIT_RPS", 5),
		RateLimitBurst:   int(floatEnv("RATE_LIMIT_BURST", 20)),
	}
	if cfg.RateLimitRPS <= 0 {
		cfg.RateLimitRPS = 5
	}
	if cfg.RateLimitBurst < 1 {
		cfg.RateLimitBurst = 10
	}
	return cfg
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func floatEnv(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func newProxy(target string, logger *log.Logger) *httputil.ReverseProxy {
	url, err := url.Parse(target)
	if err != nil {
		logger.Fatalf("invalid proxy target %s: %v", target, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(url)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = url.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Printf("proxy error: %v", err)
		writeError(w, http.StatusBadGateway, "proxy_error", "downstream unavailable")
	}
	return proxy
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.limiter.allow(clientKey(r)) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	switch {
	case r.URL.Path == "/status":
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"status": "ok"}})
		return
	case r.URL.Path == "/healthz":
		writeJSON(w, http.StatusOK, apiResponse{
			Success: true,
			Data: map[string]interface{}{
				"status": "healthy",
				"env":    s.cfg.Env,
			},
		})
		return
	case strings.HasPrefix(r.URL.Path, "/v1/users"):
		s.handleUsers(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/orders"):
		s.handleOrders(w, r)
		return
	default:
		writeError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}
}

func (s *server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/users/register") || strings.HasPrefix(r.URL.Path, "/v1/users/login") {
		s.forward(w, r, s.usersProxy, nil)
		return
	}
	claims, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	s.forward(w, r, s.usersProxy, claims)
}

func (s *server) handleOrders(w http.ResponseWriter, r *http.Request) {
	claims, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	s.forward(w, r, s.ordersProxy, claims)
}

func (s *server) forward(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, claims *tokenClaims) {
	req := r.Clone(r.Context())
	req.Header.Set("X-Forwarded-For", clientIP(r))
	if reqID, ok := r.Context().Value(ctxRequestIDKey).(string); ok {
		req.Header.Set("X-Request-ID", reqID)
	}
	if claims != nil {
		req.Header.Set("X-User-Id", claims.Subject)
		req.Header.Set("X-User-Email", claims.Email)
		req.Header.Set("X-User-Roles", strings.Join(claims.Roles, ","))
	}
	proxy.ServeHTTP(w, req)
}

func (s *server) authenticate(r *http.Request) (*tokenClaims, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, fmt.Errorf("invalid Authorization header")
	}
	return parseToken(parts[1], s.cfg.JWTSecret)
}

func parseToken(token, secret string) (*tokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token format invalid")
	}
	unsigned := parts[0] + "." + parts[1]
	if !verify(unsigned, parts[2], secret) {
		return nil, fmt.Errorf("signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode failed")
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("claims parse failed")
	}
	if claims.Exp < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}
	return &claims, nil
}

func sign(input, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verify(input, sig, secret string) bool {
	expected := sign(input, secret)
	return hmac.Equal([]byte(expected), []byte(sig))
}

func (s *server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Request-ID,X-User-Id,X-User-Email,X-User-Roles")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,DELETE,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		reqID, _ := r.Context().Value(ctxRequestIDKey).(string)
		s.logger.Printf("%s %s %d %s req_id=%s", r.Method, r.URL.Path, sw.status, time.Since(start), reqID)
	})
}

func (s *server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Printf("panic: %v", rec)
				writeError(w, http.StatusInternalServerError, "internal_error", "unexpected error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = newUUID()
		}
		ctx := context.WithValue(r.Context(), ctxRequestIDKey, reqID)
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type rateLimiter struct {
	rate  float64
	burst float64
	mu    sync.Mutex
	state map[string]*rateState
}

type rateState struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{
		rate:  rate,
		burst: float64(burst),
		state: make(map[string]*rateState),
	}
}

func (r *rateLimiter) allow(key string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	st, ok := r.state[key]
	if !ok {
		r.state[key] = &rateState{tokens: r.burst - 1, last: now}
		return true
	}

	elapsed := now.Sub(st.last).Seconds()
	st.tokens += elapsed * r.rate
	if st.tokens > r.burst {
		st.tokens = r.burst
	}
	if st.tokens < 1 {
		return false
	}
	st.tokens -= 1
	st.last = now
	return true
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clientKey(r *http.Request) string {
	return clientIP(r)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, resp apiResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiResponse{
		Success: false,
		Error: &apiError{
			Code:    code,
			Message: message,
		},
	})
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
