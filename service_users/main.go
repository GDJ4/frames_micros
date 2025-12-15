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
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	Port          string
	JWTSecret     string
	TokenTTL      time.Duration
	ServiceAPIKey string
	Env           string
}

type server struct {
	cfg    config
	store  *userStore
	logger *log.Logger
}

type ctxKey string

const (
	ctxUserKey      ctxKey = "user"
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

type user struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Roles        []string  `json:"roles"`
	PasswordHash string    `json:"-"`
	PasswordSalt string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type registerRequest struct {
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userStore struct {
	mu         sync.RWMutex
	users      map[string]user
	emailIndex map[string]string
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
	logger := log.New(os.Stdout, "service_users ", log.LstdFlags|log.LUTC)
	store := newUserStore()

	srv := &server{
		cfg:    cfg,
		store:  store,
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.Handle("/status", http.HandlerFunc(srv.handleStatus))
	mux.Handle("/healthz", http.HandlerFunc(srv.handleHealth))

	mux.Handle("/v1/users/register", srv.withCORS(http.HandlerFunc(srv.handleRegister)))
	mux.Handle("/v1/users/login", srv.withCORS(http.HandlerFunc(srv.handleLogin)))
	mux.Handle("/v1/users/me", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleMe))))
	mux.Handle("/v1/users", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleListUsers))))
	mux.Handle("/v1/users/", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleUserByID))))
	mux.Handle("/v1/internal/users/", srv.withCORS(srv.withServiceKey(http.HandlerFunc(srv.handleInternalUser))))

	root := srv.withRequestID(srv.withLogging(srv.withRecovery(mux)))

	addr := ":" + cfg.Port
	logger.Printf("starting users service on %s (env=%s)", addr, cfg.Env)

	server := &http.Server{
		Addr:         addr,
		Handler:      root,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("server failed: %v", err)
	}
}

func loadConfig() config {
	return config{
		Port:          envDefault("PORT", "9001"),
		JWTSecret:     envDefault("JWT_SECRET", "local-dev-secret"),
		TokenTTL:      durationEnv("TOKEN_TTL", 24*time.Hour),
		ServiceAPIKey: envDefault("INTERNAL_API_KEY", "internal-key"),
		Env:           envDefault("APP_ENV", "dev"),
	}
}

func envDefault(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func durationEnv(key string, def time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return def
}

func newUserStore() *userStore {
	return &userStore{
		users:      make(map[string]user),
		emailIndex: make(map[string]string),
	}
}

func (s *userStore) create(u user) (user, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existingID, ok := s.emailIndex[strings.ToLower(u.Email)]; ok {
		if _, exists := s.users[existingID]; exists {
			return user{}, fmt.Errorf("email already exists")
		}
	}

	s.users[u.ID] = u
	s.emailIndex[strings.ToLower(u.Email)] = u.ID
	return u, nil
}

func (s *userStore) getByEmail(email string) (user, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.emailIndex[strings.ToLower(email)]
	if !ok {
		return user{}, false
	}
	u, ok := s.users[id]
	return u, ok
}

func (s *userStore) getByID(id string) (user, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

func (s *userStore) update(id string, fn func(u user) (user, error)) (user, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.users[id]
	if !ok {
		return user{}, fmt.Errorf("not found")
	}
	updated, err := fn(current)
	if err != nil {
		return user{}, err
	}
	if !strings.EqualFold(current.Email, updated.Email) {
		if otherID, exists := s.emailIndex[strings.ToLower(updated.Email)]; exists && otherID != id {
			return user{}, fmt.Errorf("email already exists")
		}
		delete(s.emailIndex, strings.ToLower(current.Email))
		s.emailIndex[strings.ToLower(updated.Email)] = id
	}
	s.users[id] = updated
	return updated, nil
}

func (s *userStore) list(filter listFilter) ([]user, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	matched := make([]user, 0, len(s.users))
	for _, u := range s.users {
		if filter.email != "" && !strings.Contains(strings.ToLower(u.Email), strings.ToLower(filter.email)) {
			continue
		}
		if filter.name != "" && !strings.Contains(strings.ToLower(u.Name), strings.ToLower(filter.name)) {
			continue
		}
		if filter.role != "" && !hasRole(u.Roles, filter.role) {
			continue
		}
		matched = append(matched, u)
	}

	total := len(matched)
	start := (filter.page - 1) * filter.pageSize
	if start > total {
		return []user{}, total
	}
	end := start + filter.pageSize
	if end > total {
		end = total
	}
	return matched[start:end], total
}

type listFilter struct {
	page     int
	pageSize int
	email    string
	name     string
	role     string
}

type authUser struct {
	ID    string
	Email string
	Roles []string
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"status": "ok"}})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]string{
			"service":   "users",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	})
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}

	var req registerRequest
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	if err := validateRegister(req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if req.Roles == nil || len(req.Roles) == 0 {
		req.Roles = []string{"user"}
	}

	passwordHash, salt, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash_error", "failed to hash password")
		return
	}

	now := time.Now().UTC()
	u := user{
		ID:           newUUID(),
		Email:        strings.ToLower(req.Email),
		Name:         req.Name,
		Roles:        normalizeRoles(req.Roles),
		PasswordHash: passwordHash,
		PasswordSalt: salt,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	created, err := s.store.create(u)
	if err != nil {
		writeError(w, http.StatusConflict, "duplicate_email", "user with this email already exists")
		return
	}

	token, err := issueToken(created, s.cfg.JWTSecret, s.cfg.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_error", "failed to issue token")
		return
	}

	writeJSON(w, http.StatusCreated, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"user":  sanitizeUser(created),
			"token": token,
		},
	})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}
	var req loginRequest
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "email and password are required")
		return
	}

	u, ok := s.store.getByEmail(req.Email)
	if !ok || !verifyPassword(u.PasswordHash, u.PasswordSalt, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	token, err := issueToken(u, s.cfg.JWTSecret, s.cfg.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_error", "failed to issue token")
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]interface{}{
			"user":  sanitizeUser(u),
			"token": token,
		},
	})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	userCtx := getAuthUser(r.Context())
	if userCtx == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	u, ok := s.store.getByID(userCtx.ID)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: sanitizeUser(u)})
	case http.MethodPut, http.MethodPatch:
		var body struct {
			Name  *string  `json:"name"`
			Roles []string `json:"roles"`
		}
		if err := decodeJSON(w, r, &body, 1<<20); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		updated, err := s.store.update(userCtx.ID, func(current user) (user, error) {
			if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
				current.Name = strings.TrimSpace(*body.Name)
			}
			if len(body.Roles) > 0 {
				if !hasRole(userCtx.Roles, "admin") {
					return current, fmt.Errorf("only admin can update roles")
				}
				current.Roles = normalizeRoles(body.Roles)
			}
			current.UpdatedAt = time.Now().UTC()
			return current, nil
		})
		if err != nil {
			code := "update_error"
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "admin") {
				code = "forbidden"
				status = http.StatusForbidden
			}
			writeError(w, status, code, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: sanitizeUser(updated)})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unsupported method")
	}
}

func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	userCtx := getAuthUser(r.Context())
	if userCtx == nil || !hasRole(userCtx.Roles, "admin") {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed")
		return
	}

	page := parseIntDefault(r.URL.Query().Get("page"), 1)
	pageSize := parseIntDefault(r.URL.Query().Get("limit"), 20)
	if pageSize > 100 {
		pageSize = 100
	}
	filter := listFilter{
		page:     page,
		pageSize: pageSize,
		email:    r.URL.Query().Get("email"),
		name:     r.URL.Query().Get("name"),
		role:     r.URL.Query().Get("role"),
	}
	items, total := s.store.list(filter)

	resp := map[string]interface{}{
		"items":     sanitizeUsers(items),
		"page":      page,
		"limit":     pageSize,
		"total":     total,
		"hasNext":   page*pageSize < total,
		"hasPrev":   page > 1,
		"timestamp": time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: resp})
}

func (s *server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	userCtx := getAuthUser(r.Context())
	if userCtx == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) != 3 {
		writeError(w, http.StatusNotFound, "not_found", "unknown route")
		return
	}
	id := segments[2]

	target, ok := s.store.getByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}

	if !hasRole(userCtx.Roles, "admin") && userCtx.ID != id {
		writeError(w, http.StatusForbidden, "forbidden", "not enough rights")
		return
	}

	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: sanitizeUser(target)})
		return
	}

	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed")
}

func (s *server) handleInternalUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed")
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) != 4 { // /v1/internal/users/{id}
		writeError(w, http.StatusNotFound, "not_found", "unknown route")
		return
	}
	id := segments[3]
	u, ok := s.store.getByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: sanitizeUser(u)})
}

func validateRegister(req registerRequest) error {
	if strings.TrimSpace(req.Email) == "" || !strings.Contains(req.Email, "@") {
		return fmt.Errorf("valid email is required")
	}
	if len(req.Password) < 6 {
		return fmt.Errorf("password must be at least 6 characters")
	}
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

func issueToken(u user, secret string, ttl time.Duration) (string, error) {
	claims := tokenClaims{
		Subject: u.ID,
		Email:   u.Email,
		Roles:   u.Roles,
		Exp:     time.Now().Add(ttl).Unix(),
		Issued:  time.Now().Unix(),
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := header + "." + payload
	sig := sign(unsigned, secret)
	return unsigned + "." + sig, nil
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

func hashPassword(password string) (string, string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	saltStr := base64.RawStdEncoding.EncodeToString(salt)
	sum := sha256.Sum256(append([]byte(saltStr), password...))
	return base64.RawStdEncoding.EncodeToString(sum[:]), saltStr, nil
}

func verifyPassword(hash, salt, password string) bool {
	sum := sha256.Sum256(append([]byte(salt), password...))
	return base64.RawStdEncoding.EncodeToString(sum[:]) == hash
}

func sanitizeUser(u user) user {
	u.PasswordHash = ""
	u.PasswordSalt = ""
	return u
}

func sanitizeUsers(users []user) []user {
	out := make([]user, 0, len(users))
	for _, u := range users {
		out = append(out, sanitizeUser(u))
	}
	return out
}

func normalizeRoles(roles []string) []string {
	unique := make(map[string]struct{})
	for _, r := range roles {
		trimmed := strings.TrimSpace(strings.ToLower(r))
		if trimmed == "" {
			continue
		}
		unique[trimmed] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for r := range unique {
		result = append(result, r)
	}
	if len(result) == 0 {
		return []string{"user"}
	}
	return result
}

func hasRole(roles []string, target string) bool {
	target = strings.ToLower(target)
	for _, r := range roles {
		if strings.ToLower(r) == target {
			return true
		}
	}
	return false
}

func parseIntDefault(value string, def int) int {
	if value == "" {
		return def
	}
	v, err := strconv.Atoi(value)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func (s *server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing Authorization header")
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid Authorization header")
			return
		}
		claims, err := parseToken(parts[1], s.cfg.JWTSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey, &authUser{
			ID:    claims.Subject,
			Email: claims.Email,
			Roles: claims.Roles,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *server) withServiceKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Service-Key")
		if key == "" || key != s.cfg.ServiceAPIKey {
			writeError(w, http.StatusForbidden, "forbidden", "invalid service key")
			return
		}
		next.ServeHTTP(w, r)
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

func (s *server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		reqID, _ := r.Context().Value(ctxRequestIDKey).(string)
		s.logger.Printf("%s %s %d %s req_id=%s", r.Method, r.URL.Path, sw.status, time.Since(start), reqID)
	})
}

func (s *server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Request-ID,X-Service-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
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

func getAuthUser(ctx context.Context) *authUser {
	val := ctx.Value(ctxUserKey)
	if val == nil {
		return nil
	}
	if au, ok := val.(*authUser); ok {
		return au
	}
	return nil
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	// set version 4 and variant bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
