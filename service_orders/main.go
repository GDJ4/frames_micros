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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	Port           string
	Env            string
	JWTSecret      string
	ServiceAPIKey  string
	UsersService   string
	HTTPTimeout    time.Duration
	DefaultPage    int
	DefaultPerPage int
}

type server struct {
	cfg    config
	store  *orderStore
	events *eventStore
	client *http.Client
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

type authUser struct {
	ID    string
	Email string
	Roles []string
}

type tokenClaims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Roles   []string `json:"roles"`
	Exp     int64    `json:"exp"`
	Issued  int64    `json:"iat"`
}

type orderItem struct {
	Product  string  `json:"product"`
	Quantity int     `json:"quantity"`
	Price    float64 `json:"price"`
}

type order struct {
	ID        string      `json:"id"`
	UserID    string      `json:"userId"`
	Items     []orderItem `json:"items"`
	Status    string      `json:"status"`
	Total     float64     `json:"total"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
}

type orderStore struct {
	mu     sync.RWMutex
	orders map[string]order
}

type orderFilter struct {
	userID   string
	status   string
	page     int
	pageSize int
	sortBy   string
	sortDir  string
}

type domainEvent struct {
	ID        string      `json:"id"`
	Type      string      `json:"type"`
	OrderID   string      `json:"orderId"`
	UserID    string      `json:"userId"`
	Status    string      `json:"status"`
	CreatedAt time.Time   `json:"createdAt"`
	Payload   interface{} `json:"payload,omitempty"`
}

type eventStore struct {
	mu     sync.RWMutex
	events []domainEvent
}

func main() {
	cfg := loadConfig()
	logger := log.New(os.Stdout, "service_orders ", log.LstdFlags|log.LUTC)

	srv := &server{
		cfg:    cfg,
		store:  newOrderStore(),
		events: &eventStore{},
		client: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.Handle("/status", http.HandlerFunc(srv.handleStatus))
	mux.Handle("/healthz", http.HandlerFunc(srv.handleHealth))

	mux.Handle("/v1/orders/events", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleEvents))))
	mux.Handle("/v1/orders", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleOrders))))
	mux.Handle("/v1/orders/", srv.withCORS(srv.withAuth(http.HandlerFunc(srv.handleOrderByID))))

	root := srv.withRequestID(srv.withLogging(srv.withRecovery(mux)))

	addr := ":" + cfg.Port
	logger.Printf("starting orders service on %s (env=%s)", addr, cfg.Env)

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
		Port:           envDefault("PORT", "9002"),
		Env:            envDefault("APP_ENV", "dev"),
		JWTSecret:      envDefault("JWT_SECRET", "local-dev-secret"),
		ServiceAPIKey:  envDefault("INTERNAL_API_KEY", "internal-key"),
		UsersService:   envDefault("USERS_SERVICE_URL", "http://service_users:9001"),
		HTTPTimeout:    durationEnv("HTTP_TIMEOUT", 5*time.Second),
		DefaultPage:    1,
		DefaultPerPage: 20,
	}
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func newOrderStore() *orderStore {
	return &orderStore{orders: make(map[string]order)}
}

func (s *orderStore) create(o order) order {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orders[o.ID] = o
	return o
}

func (s *orderStore) get(id string) (order, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orders[id]
	return o, ok
}

func (s *orderStore) update(id string, fn func(order) (order, error)) (order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.orders[id]
	if !ok {
		return order{}, fmt.Errorf("not found")
	}
	updated, err := fn(current)
	if err != nil {
		return order{}, err
	}
	s.orders[id] = updated
	return updated, nil
}

func (s *orderStore) list(filter orderFilter) ([]order, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]order, 0, len(s.orders))
	for _, o := range s.orders {
		if filter.userID != "" && o.UserID != filter.userID {
			continue
		}
		if filter.status != "" && o.Status != filter.status {
			continue
		}
		items = append(items, o)
	}

	sort.Slice(items, func(i, j int) bool {
		switch filter.sortBy {
		case "total":
			if filter.sortDir == "asc" {
				return items[i].Total < items[j].Total
			}
			return items[i].Total > items[j].Total
		default:
			if filter.sortDir == "asc" {
				return items[i].CreatedAt.Before(items[j].CreatedAt)
			}
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
	})

	total := len(items)
	start := (filter.page - 1) * filter.pageSize
	if start > total {
		return []order{}, total
	}
	end := start + filter.pageSize
	if end > total {
		end = total
	}
	return items[start:end], total
}

func (e *eventStore) add(event domainEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append([]domainEvent{event}, e.events...)
	if len(e.events) > 200 {
		e.events = e.events[:200]
	}
}

func (e *eventStore) list() []domainEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	copyEvents := make([]domainEvent, len(e.events))
	copy(copyEvents, e.events)
	return copyEvents
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: map[string]string{"status": "ok"}})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apiResponse{
		Success: true,
		Data: map[string]string{
			"service":   "orders",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	})
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	user := getAuthUser(r.Context())
	if user == nil || !hasRole(user.Roles, "admin") {
		writeError(w, http.StatusForbidden, "forbidden", "admin rights required")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed")
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: s.events.list()})
}

func (s *server) handleOrders(w http.ResponseWriter, r *http.Request) {
	user := getAuthUser(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleListOrders(w, r, user)
	case http.MethodPost:
		s.handleCreateOrder(w, r, user)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unsupported method")
	}
}

func (s *server) handleListOrders(w http.ResponseWriter, r *http.Request, user *authUser) {
	q := r.URL.Query()
	page := parseIntDefault(q.Get("page"), s.cfg.DefaultPage)
	limit := parseIntDefault(q.Get("limit"), s.cfg.DefaultPerPage)
	if limit > 100 {
		limit = 100
	}
	filter := orderFilter{
		page:     page,
		pageSize: limit,
		status:   strings.TrimSpace(q.Get("status")),
		sortBy:   strings.TrimSpace(q.Get("sortBy")),
		sortDir:  strings.ToLower(strings.TrimSpace(q.Get("sortDir"))),
	}
	if filter.sortBy == "" {
		filter.sortBy = "createdAt"
	}
	if filter.sortDir != "asc" {
		filter.sortDir = "desc"
	}

	if hasRole(user.Roles, "admin") && q.Get("userId") != "" {
		filter.userID = q.Get("userId")
	} else {
		filter.userID = user.ID
	}

	items, total := s.store.list(filter)
	resp := map[string]interface{}{
		"items":     items,
		"page":      page,
		"limit":     limit,
		"total":     total,
		"hasNext":   page*limit < total,
		"hasPrev":   page > 1,
		"timestamp": time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: resp})
}

func (s *server) handleCreateOrder(w http.ResponseWriter, r *http.Request, user *authUser) {
	var body struct {
		Items []orderItem `json:"items"`
	}
	if err := decodeJSON(w, r, &body, 1<<20); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if len(body.Items) == 0 {
		writeError(w, http.StatusBadRequest, "validation_error", "order must contain at least one item")
		return
	}
	for i, item := range body.Items {
		if strings.TrimSpace(item.Product) == "" {
			writeError(w, http.StatusBadRequest, "validation_error", fmt.Sprintf("item %d product is required", i))
			return
		}
		if item.Quantity <= 0 {
			writeError(w, http.StatusBadRequest, "validation_error", fmt.Sprintf("item %d quantity must be > 0", i))
			return
		}
		if item.Price < 0 {
			writeError(w, http.StatusBadRequest, "validation_error", fmt.Sprintf("item %d price must be >= 0", i))
			return
		}
	}

	reqID, _ := r.Context().Value(ctxRequestIDKey).(string)
	if err := s.ensureUserExists(user.ID, reqID); err != nil {
		if errors.Is(err, errUserNotFound) {
			writeError(w, http.StatusBadRequest, "user_not_found", "user does not exist in users service")
			return
		}
		writeError(w, http.StatusBadGateway, "users_service_error", err.Error())
		return
	}

	now := time.Now().UTC()
	total := calculateTotal(body.Items)
	o := order{
		ID:        newUUID(),
		UserID:    user.ID,
		Items:     body.Items,
		Status:    "created",
		Total:     total,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.store.create(o)
	s.events.add(domainEvent{
		ID:        newUUID(),
		Type:      "order.created",
		OrderID:   o.ID,
		UserID:    o.UserID,
		Status:    o.Status,
		CreatedAt: now,
		Payload:   map[string]interface{}{"total": total},
	})

	writeJSON(w, http.StatusCreated, apiResponse{Success: true, Data: o})
}

func (s *server) handleOrderByID(w http.ResponseWriter, r *http.Request) {
	user := getAuthUser(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		writeError(w, http.StatusNotFound, "not_found", "unknown route")
		return
	}
	id := parts[2]

	if len(parts) == 4 && parts[3] == "cancel" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is allowed")
			return
		}
		s.handleCancel(w, r, user, id)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetOrder(w, r, user, id)
	case http.MethodPatch:
		s.handleUpdateStatus(w, r, user, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unsupported method")
	}
}

func (s *server) handleGetOrder(w http.ResponseWriter, r *http.Request, user *authUser, id string) {
	o, ok := s.store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "order not found")
		return
	}
	if !hasRole(user.Roles, "admin") && o.UserID != user.ID {
		writeError(w, http.StatusForbidden, "forbidden", "access denied")
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: o})
}

func (s *server) handleUpdateStatus(w http.ResponseWriter, r *http.Request, user *authUser, id string) {
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(w, r, &body, 1<<20); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	newStatus := strings.ToLower(strings.TrimSpace(body.Status))
	if newStatus == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "status is required")
		return
	}

	updated, err := s.store.update(id, func(current order) (order, error) {
		if !hasRole(user.Roles, "admin") && current.UserID != user.ID {
			return current, fmt.Errorf("forbidden")
		}
		if current.Status == "done" || current.Status == "cancelled" {
			return current, fmt.Errorf("order is immutable in final status")
		}
		if !isValidStatus(newStatus) {
			return current, fmt.Errorf("invalid status")
		}
		if !hasRole(user.Roles, "admin") && newStatus != "cancelled" {
			return current, fmt.Errorf("only admin can change status except cancel")
		}
		if !allowedTransition(current.Status, newStatus) {
			return current, fmt.Errorf("invalid transition from %s to %s", current.Status, newStatus)
		}
		current.Status = newStatus
		current.UpdatedAt = time.Now().UTC()
		return current, nil
	})
	if err != nil {
		status := http.StatusBadRequest
		code := "update_error"
		msg := err.Error()
		if strings.Contains(err.Error(), "forbidden") {
			status = http.StatusForbidden
			code = "forbidden"
			msg = "access denied"
		}
		writeError(w, status, code, msg)
		return
	}
	s.events.add(domainEvent{
		ID:        newUUID(),
		Type:      "order.status_updated",
		OrderID:   updated.ID,
		UserID:    updated.UserID,
		Status:    updated.Status,
		CreatedAt: time.Now().UTC(),
	})
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: updated})
}

func (s *server) handleCancel(w http.ResponseWriter, r *http.Request, user *authUser, id string) {
	updated, err := s.store.update(id, func(current order) (order, error) {
		if !hasRole(user.Roles, "admin") && current.UserID != user.ID {
			return current, fmt.Errorf("forbidden")
		}
		if current.Status == "cancelled" {
			return current, fmt.Errorf("already cancelled")
		}
		if current.Status == "done" {
			return current, fmt.Errorf("order already completed")
		}
		current.Status = "cancelled"
		current.UpdatedAt = time.Now().UTC()
		return current, nil
	})
	if err != nil {
		status := http.StatusBadRequest
		code := "cancel_error"
		if strings.Contains(err.Error(), "forbidden") {
			status = http.StatusForbidden
			code = "forbidden"
		}
		writeError(w, status, code, err.Error())
		return
	}
	s.events.add(domainEvent{
		ID:        newUUID(),
		Type:      "order.cancelled",
		OrderID:   updated.ID,
		UserID:    updated.UserID,
		Status:    updated.Status,
		CreatedAt: time.Now().UTC(),
	})
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: updated})
}

var errUserNotFound = fmt.Errorf("user_not_found")

func (s *server) ensureUserExists(userID, requestID string) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/internal/users/%s", strings.TrimSuffix(s.cfg.UsersService, "/"), userID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Service-Key", s.cfg.ServiceAPIKey)
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errUserNotFound
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("users service returned %d", resp.StatusCode)
	}
	return nil
}

func calculateTotal(items []orderItem) float64 {
	var total float64
	for _, it := range items {
		total += float64(it.Quantity) * it.Price
	}
	return total
}

func isValidStatus(status string) bool {
	switch status {
	case "created", "in_progress", "done", "cancelled":
		return true
	default:
		return false
	}
}

func allowedTransition(current, next string) bool {
	if current == next {
		return true
	}
	switch current {
	case "created":
		return next == "in_progress" || next == "cancelled" || next == "done"
	case "in_progress":
		return next == "done" || next == "cancelled"
	default:
		return false
	}
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

func hasRole(roles []string, target string) bool {
	target = strings.ToLower(target)
	for _, r := range roles {
		if strings.ToLower(r) == target {
			return true
		}
	}
	return false
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

func (s *server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Request-ID")
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
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
