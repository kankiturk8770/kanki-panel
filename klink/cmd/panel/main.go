package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kankipro/klink/internal/store"
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
	return cfg, nil
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
	errCh := make(chan error, 1)
	go func() {
		log.Info("KLINK panel started", "address", cfg.Listen, "tls", cfg.TLSCertFile != "")
		if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
			errCh <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
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
	log.Info("KLINK panel stopped")
}
