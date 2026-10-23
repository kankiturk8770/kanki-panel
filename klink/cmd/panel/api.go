package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const adminCookie = "klink_admin"

// secureAdminCookie نام کوکی روی HTTPS است. پیشوند __Host- مرورگر را وادار
// می‌کند کوکی را فقط با Secure، بدون Domain و با Path=/ بپذیرد؛ بنابراین
// زیردامنه‌ی دیگر یا اتصال HTTP نمی‌تواند آن را بازنویسی کند.
const secureAdminCookie = "__Host-klink_admin"

const (
	maxAdminSessions  = 32
	maxTrackedIPs     = 10000
	loginBurst        = 5
	loginBlock        = 15 * time.Minute
	concurrentBcrypts = 4
)

type adminSession struct {
	expires time.Time
}

type app struct {
	cfg  Config
	db   *store.Store
	log  *slog.Logger
	http *http.Client

	mu       sync.Mutex
	sessions map[string]adminSession
	failures map[string]*loginFailures
	// bcrypt عمداً کند است؛ این سمافور جلوی مصرف کامل CPU با درخواست‌های
	// ورود موازی از IPهای زیاد را می‌گیرد.
	bcryptSlots chan struct{}
}

type loginFailures struct {
	count   int
	blocked time.Time
}

func newApp(cfg Config, db *store.Store, log *slog.Logger) *app {
	return &app{cfg: cfg, db: db, log: log, http: &http.Client{Timeout: 3 * time.Second},
		sessions: make(map[string]adminSession), failures: make(map[string]*loginFailures),
		bcryptSlots: make(chan struct{}, concurrentBcrypts)}
}

func (a *app) cookieName() string {
	if a.cfg.SecureCookies {
		return secureAdminCookie
	}
	return adminCookie
}

// noDirFS فهرست پوشه‌ها را نمایش نمی‌دهد و فایل‌های پنهان را سرو نمی‌کند.
type noDirFS struct{ http.FileSystem }

func (fs noDirFS) Open(name string) (http.File, error) {
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") {
			return nil, os.ErrNotExist
		}
	}
	f, err := fs.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil && st.IsDir() {
		index, err := fs.FileSystem.Open(path.Join(name, "index.html"))
		if err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
		index.Close()
	}
	return f, nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", a.requireCSRF(a.login))
	mux.HandleFunc("POST /api/logout", a.requireAuth(a.requireCSRF(a.logout)))
	mux.HandleFunc("GET /api/me", a.requireAuth(a.me))
	mux.HandleFunc("GET /api/dashboard", a.requireAuth(a.dashboard))
	mux.HandleFunc("GET /api/users", a.requireAuth(a.listUsers))
	mux.HandleFunc("POST /api/users", a.requireAuth(a.requireCSRF(a.createUser)))
	mux.HandleFunc("GET /api/users/{id}", a.requireAuth(a.getUser))
	mux.HandleFunc("PUT /api/users/{id}", a.requireAuth(a.requireCSRF(a.updateUser)))
	mux.HandleFunc("DELETE /api/users/{id}", a.requireAuth(a.requireCSRF(a.deleteUser)))
	mux.HandleFunc("POST /api/users/{id}/reset", a.requireAuth(a.requireCSRF(a.resetUser)))
	mux.HandleFunc("POST /api/users/{id}/rotate-token", a.requireAuth(a.requireCSRF(a.rotateToken)))
	mux.HandleFunc("GET /sub/{token}", a.subscription)
	static := http.FileServer(noDirFS{http.Dir(a.cfg.WebRoot)})
	mux.Handle("GET /", static)
	return a.securityHeaders(a.recoverPanics(mux))
}

func (a *app) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// Tailwind به‌صورت فایل محلی ساخته شده است؛ هیچ اسکریپت شخص ثالثی (CDN)
		// با دسترسی کامل به پنل مدیریت اجرا نمی‌شود و پنل بدون اینترنت آزاد هم
		// درست نمایش داده می‌شود.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				a.log.Error("HTTP panic", "path", r.URL.Path, "panic", v)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *app) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-KLINK-Request") != "1" {
			writeError(w, http.StatusForbidden, "missing request header")
			return
		}
		// دفاع دوم در برابر CSRF: درخواست تغییر فقط از همان origin پنل.
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			writeError(w, http.StatusForbidden, "cross-site request rejected")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				writeError(w, http.StatusForbidden, "cross-origin request rejected")
				return
			}
		}
		next(w, r)
	}
}

func (a *app) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(a.cookieName())
		if err != nil || !a.validSession(cookie.Value) {
			w.Header().Set("WWW-Authenticate", "Cookie")
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r)
	}
}

func randomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *app) validSession(token string) bool {
	if len(token) != 43 {
		return false
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[token]
	if ok && !now.Before(s.expires) {
		delete(a.sessions, token)
		return false
	}
	return ok
}

// addSessionLocked نشست تازه را ثبت می‌کند؛ نشست‌های منقضی پاک و تعداد نشست‌های
// هم‌زمان محدود می‌شود (قدیمی‌ترین بیرون می‌رود).
func (a *app) addSessionLocked(token string, expires time.Time) {
	now := time.Now()
	for t, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, t)
		}
	}
	for len(a.sessions) >= maxAdminSessions {
		var oldest string
		for t, s := range a.sessions {
			if oldest == "" || s.expires.Before(a.sessions[oldest].expires) {
				oldest = t
			}
		}
		delete(a.sessions, oldest)
	}
	a.sessions[token] = adminSession{expires: expires}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// تلاش پیش از بررسی رمز رزرو می‌شود. قبلاً شمارش پس از bcrypt انجام می‌شد و
	// مهاجم با ارسال صدها درخواست هم‌زمان محدودیت پنج‌تایی را دور می‌زد.
	now := time.Now()
	a.mu.Lock()
	if len(a.failures) >= maxTrackedIPs {
		for k, f := range a.failures {
			if now.After(f.blocked) {
				delete(a.failures, k)
			}
		}
	}
	f := a.failures[ip]
	if f == nil {
		f = &loginFailures{}
		a.failures[ip] = f
	}
	if now.Before(f.blocked) {
		a.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too many login attempts; retry later")
		return
	}
	f.count++
	if f.count >= loginBurst {
		f.blocked = now.Add(loginBlock)
		f.count = 0
	}
	a.mu.Unlock()

	select {
	case a.bcryptSlots <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	usernameOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(a.cfg.AdminUsername)) == 1
	passwordOK := bcrypt.CompareHashAndPassword([]byte(a.cfg.AdminPasswordHash), []byte(req.Password)) == nil
	<-a.bcryptSlots
	if !usernameOK || !passwordOK {
		a.log.Warn("admin login failed", "ip", ip)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	ttl := time.Duration(a.cfg.SessionTTLHours) * time.Hour
	a.mu.Lock()
	delete(a.failures, ip)
	a.addSessionLocked(token, time.Now().Add(ttl))
	a.mu.Unlock()
	a.log.Info("admin login", "ip", ip)
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: token, Path: "/", HttpOnly: true,
		Secure: a.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"username": a.cfg.AdminUsername})
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(a.cookieName()); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: "", Path: "/", HttpOnly: true,
		Secure: a.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) me(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"username": a.cfg.AdminUsername})
}

func (a *app) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	totals, err := a.db.Totals(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	response := map[string]any{"core_online": false, "database": totals, "core": nil}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.CoreStatusURL, nil)
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+a.cfg.CoreStatusToken)
		resp, requestErr := a.http.Do(req)
		if requestErr == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var core map[string]any
				if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&core) == nil {
					response["core_online"] = true
					response["core"] = core
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, response)
}

type userView struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	PublicKey       string     `json:"public_key"`
	Enabled         bool       `json:"enabled"`
	VolumeLimit     int64      `json:"volume_limit"`
	VolumeLimitGB   float64    `json:"volume_limit_gb"`
	UsedBytes       int64      `json:"used_bytes"`
	RemainingBytes  int64      `json:"remaining_bytes"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	DeviceLimit     int        `json:"device_limit"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	SubscriptionURL string     `json:"subscription_url"`
}

func (a *app) view(u *store.User) userView {
	remaining := int64(0)
	if u.VolumeLimit > 0 {
		remaining = max(0, u.VolumeLimit-u.UsedBytes)
	}
	return userView{ID: u.ID, Name: u.Name, PublicKey: u.PublicKey, Enabled: u.Enabled,
		VolumeLimit: u.VolumeLimit, VolumeLimitGB: float64(u.VolumeLimit) / (1 << 30),
		UsedBytes: u.UsedBytes, RemainingBytes: remaining, ExpiresAt: u.ExpiresAt,
		DeviceLimit: u.DeviceLimit, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
		SubscriptionURL: strings.TrimRight(a.cfg.PublicURL, "/") + "/sub/" + u.Token}
}

func (a *app) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.db.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	result := make([]userView, 0, len(users))
	for _, u := range users {
		result = append(result, a.view(u))
	}
	writeJSON(w, http.StatusOK, result)
}

func userID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(path.Base(r.URL.Path), 10, 64)
	// For action routes the last segment is not the ID; use the explicit value.
	if value := r.PathValue("id"); value != "" {
		id, err = strconv.ParseInt(value, 10, 64)
	}
	if err != nil || id <= 0 {
		return 0, errors.New("invalid user id")
	}
	return id, nil
}

func (a *app) getUser(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := a.db.GetUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	writeJSON(w, http.StatusOK, a.view(u))
}

type userRequest struct {
	Name          string  `json:"name"`
	Enabled       *bool   `json:"enabled"`
	VolumeLimitGB float64 `json:"volume_limit_gb"`
	ExpiresAt     string  `json:"expires_at"`
	DeviceLimit   int     `json:"device_limit"`
}

func (r *userRequest) apply(u *store.User, creating bool) error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len([]rune(r.Name)) > 64 {
		return errors.New("name must contain 1 to 64 characters")
	}
	if math.IsNaN(r.VolumeLimitGB) || math.IsInf(r.VolumeLimitGB, 0) || r.VolumeLimitGB < 0 || r.VolumeLimitGB > 1<<20 {
		return errors.New("volume limit is outside the allowed range")
	}
	if r.DeviceLimit < 0 || r.DeviceLimit > 10000 {
		return errors.New("device limit must be between 0 (unlimited) and 10000")
	}
	u.Name = r.Name
	u.VolumeLimit = int64(math.Round(r.VolumeLimitGB * (1 << 30)))
	u.DeviceLimit = r.DeviceLimit
	if r.Enabled != nil {
		u.Enabled = *r.Enabled
	} else if creating {
		u.Enabled = true
	}
	u.ExpiresAt = nil
	if value := strings.TrimSpace(r.ExpiresAt); value != "" {
		var t time.Time
		var err error
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
			t, err = time.Parse(layout, value)
			if err == nil {
				break
			}
		}
		if err != nil {
			return errors.New("expiration must be RFC3339, YYYY-MM-DD, or YYYY-MM-DDTHH:mm")
		}
		t = t.UTC()
		u.ExpiresAt = &t
	}
	return nil
}

func (a *app) createUser(w http.ResponseWriter, r *http.Request) {
	var req userRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	key, err := kcrypto.GenerateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	u := &store.User{PublicKey: key.PublicBase64(), PrivateKey: key.PrivateBase64(), Token: token}
	if err := req.apply(u, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.db.CreateUser(r.Context(), u); err != nil {
		writeError(w, http.StatusConflict, "could not create user")
		return
	}
	writeJSON(w, http.StatusCreated, a.view(u))
}

func (a *app) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req userRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := a.db.GetUser(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err := req.apply(u, false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.db.UpdateUser(r.Context(), u); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	writeJSON(w, http.StatusOK, a.view(u))
}

func (a *app) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err == nil {
		err = a.db.DeleteUser(r.Context(), id)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) resetUser(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err == nil {
		err = a.db.ResetUsage(r.Context(), id)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not reset usage")
		return
	}
	a.getUser(w, r)
}

func (a *app) rotateToken(w http.ResponseWriter, r *http.Request) {
	id, err := userID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	token, err := randomToken(32)
	if err == nil {
		err = a.db.RotateToken(r.Context(), id, token)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not rotate token")
		return
	}
	a.getUser(w, r)
}

func (a *app) subscription(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if len(token) != 43 {
		writeError(w, http.StatusNotFound, "subscription not found")
		return
	}
	u, err := a.db.GetByToken(r.Context(), token)
	if err != nil || !u.Enabled || u.Expired(time.Now()) || u.PrivateKey == "" {
		writeError(w, http.StatusNotFound, "subscription not found")
		return
	}
	transports := make([]map[string]string, 0, 2)
	if a.cfg.UDPEndpoint != "" {
		transports = append(transports, map[string]string{"network": "udp", "endpoint": a.cfg.UDPEndpoint})
	}
	if a.cfg.TCPEndpoint != "" {
		transports = append(transports, map[string]string{"network": "tcp", "endpoint": a.cfg.TCPEndpoint})
	}
	response := map[string]any{
		"klink_version": 1, "name": u.Name,
		"client_private_key": u.PrivateKey, "client_public_key": u.PublicKey,
		"server_public_key": a.cfg.ServerPublicKey, "transports": transports,
		"obfuscation": a.cfg.Obfuscation, "rekey_interval_seconds": 900,
		"rekey_packets": 1 << 20, "session_id_bits": 128,
	}
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Content-Disposition", `attachment; filename="klink-v1.json"`)
	writeJSON(w, http.StatusOK, response)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "only one JSON value is allowed")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message, "status": status})
}

func (a *app) String() string {
	return fmt.Sprintf("panel(users-db=%s)", a.cfg.Database)
}
