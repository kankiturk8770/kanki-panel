package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kankipro/klink/internal/store"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Listen            string `json:"listen"`
	Database          string `json:"database"`
	WebRoot           string `json:"web_root"`
	AdminUsername     string `json:"admin_username"`
	AdminPasswordHash string `json:"admin_password_hash"`
	PublicURL         string `json:"public_url"`
	CoreStatusURL     string `json:"core_status_url"`
	CoreStatusToken   string `json:"core_status_token"`
	ServerPublicKey   string `json:"server_public_key"`
	UDPEndpoint       string `json:"udp_endpoint"`
	TCPEndpoint       string `json:"tcp_endpoint"`
	Obfuscation       string `json:"obfuscation"`
	TLSCertFile       string `json:"tls_cert_file"`
	TLSKeyFile        string `json:"tls_key_file"`
	SecureCookies     bool   `json:"secure_cookies"`
	SessionTTLHours   int    `json:"session_ttl_hours"`

	// SSL خودکار با Let's Encrypt. اگر acme_domain تنظیم شود، پنل گواهی همان
	// دامنه را خودش می‌گیرد و پیش از انقضا تمدید می‌کند. اعتبارسنجی HTTP-01 روی
	// acme_http_listen (پیش‌فرض :80) انجام می‌شود و همان پورت بقیه‌ی درخواست‌ها را
	// به HTTPS هدایت می‌کند.
	ACMEDomain     string `json:"acme_domain,omitempty"`
	ACMEEmail      string `json:"acme_email,omitempty"`
	ACMECacheDir   string `json:"acme_cache_dir,omitempty"`
	ACMEHTTPListen string `json:"acme_http_listen,omitempty"`
	// ACMEDirectoryURL فقط برای تست با staging؛ خالی یعنی Let's Encrypt اصلی.
	ACMEDirectoryURL string `json:"acme_directory_url,omitempty"`
}

func (c Config) tlsEnabled() bool {
	return c.ACMEDomain != "" || c.TLSCertFile != "" || c.TLSKeyFile != ""
}

func defaultConfig() Config {
	return Config{Listen: ":8080", Database: "/var/lib/klink/klink.db", WebRoot: "web",
		AdminUsername: "admin", PublicURL: "http://127.0.0.1:8080",
		CoreStatusURL: "http://127.0.0.1:9091/v1/status", Obfuscation: "random", SessionTTLHours: 12}
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	if cfg.AdminPasswordHash == "" || cfg.CoreStatusToken == "" || cfg.ServerPublicKey == "" {
		return cfg, errors.New("admin_password_hash, core_status_token and server_public_key are required")
	}
	if cfg.UDPEndpoint == "" && cfg.TCPEndpoint == "" {
		return cfg, errors.New("at least one public proxy endpoint is required")
	}
	if cfg.SessionTTLHours <= 0 {
		cfg.SessionTTLHours = 12
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return cfg, errors.New("tls_cert_file and tls_key_file must be set together")
	}
	if cfg.ACMEDomain != "" {
		cfg.ACMEDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.ACMEDomain), "."))
		if net.ParseIP(cfg.ACMEDomain) != nil || !strings.Contains(cfg.ACMEDomain, ".") {
			return cfg, errors.New("acme_domain must be a DNS name (Let's Encrypt is not used for bare IP addresses)")
		}
		if cfg.ACMECacheDir == "" {
			cfg.ACMECacheDir = "/var/lib/klink/acme"
		}
		if cfg.ACMEHTTPListen == "" {
			cfg.ACMEHTTPListen = ":80"
		}
	}
	if cfg.tlsEnabled() {
		// روی HTTPS کوکی مدیریت هرگز نباید روی HTTP ساده فرستاده شود.
		cfg.SecureCookies = true
	} else if u, err := url.Parse(cfg.PublicURL); err == nil && u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		fmt.Fprintln(os.Stderr, "warning: panel is served over plain HTTP; admin cookie and subscription keys are not protected in transit")
	}
	return cfg, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func main() {
	configPath := flag.String("config", "/etc/klink/panel.json", "path to panel JSON configuration")
	hashPassword := flag.Bool("hash-password", false, "hash KLINK_PASSWORD or standard input and exit")
	flag.Parse()
	if *hashPassword {
		password := os.Getenv("KLINK_PASSWORD")
		if password == "" {
			fmt.Fprint(os.Stderr, "Password: ")
			var b []byte
			buf := make([]byte, 1)
			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 && buf[0] != '\n' && buf[0] != '\r' {
					b = append(b, buf[0])
				}
				if err != nil || (n > 0 && buf[0] == '\n') {
					break
				}
			}
			password = string(b)
		}
		if len(password) < 12 {
			fmt.Fprintln(os.Stderr, "password must contain at least 12 characters")
			os.Exit(1)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(hash))
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	db, err := store.Open(cfg.Database)
	if err != nil {
		log.Error("database open failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	app := newApp(cfg, db, log)
	server := &http.Server{Addr: cfg.Listen, Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 2)
	var redirect *http.Server
	if cfg.ACMEDomain != "" {
		if err := os.MkdirAll(cfg.ACMECacheDir, 0o700); err != nil {
			log.Error("ACME cache directory", "error", err)
			os.Exit(1)
		}
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.ACMEDomain),
			Cache:      autocert.DirCache(cfg.ACMECacheDir),
			Email:      cfg.ACMEEmail,
		}
		if cfg.ACMEDirectoryURL != "" {
			manager.Client = newACMEClient(cfg.ACMEDirectoryURL)
		}
		server.TLSConfig = manager.TLSConfig()
		server.TLSConfig.MinVersion = tls.VersionTLS12
		redirect = &http.Server{Addr: cfg.ACMEHTTPListen, Handler: manager.HTTPHandler(httpsRedirect(cfg)),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
			IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
		go func() {
			log.Info("ACME HTTP-01 and HTTPS redirect listener started", "address", cfg.ACMEHTTPListen, "domain", cfg.ACMEDomain)
			if err := redirect.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("ACME HTTP listener: %w", err)
			}
		}()
	} else if cfg.TLSCertFile != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	go func() {
		log.Info("KLINK panel started", "address", cfg.Listen, "tls", cfg.tlsEnabled(), "acme_domain", cfg.ACMEDomain)
		switch {
		case cfg.ACMEDomain != "":
			errCh <- server.ListenAndServeTLS("", "")
		case cfg.TLSCertFile != "":
			errCh <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		default:
			errCh <- server.ListenAndServe()
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server failed", "error", err)
			stop()
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	if redirect != nil {
		_ = redirect.Shutdown(shutdownCtx)
	}
	log.Info("KLINK panel stopped")
}

// httpsRedirect هر درخواست HTTP غیر ACME را به آدرس HTTPS پنل می‌برد.
func httpsRedirect(cfg Config) http.Handler {
	_, port, _ := net.SplitHostPort(cfg.Listen)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := cfg.ACMEDomain
		if port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		target := url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
	})
}

func newACMEClient(directoryURL string) *acme.Client {
	return &acme.Client{DirectoryURL: directoryURL}
}
