package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/mux"
	"github.com/kankipro/klink/internal/obfuscation"
	"github.com/kankipro/klink/internal/session"
	"github.com/kankipro/klink/internal/store"
	"github.com/kankipro/klink/internal/transport"
)

type duration struct{ time.Duration }

func (d *duration) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err == nil {
		v, err := time.ParseDuration(text)
		d.Duration = v
		return err
	}
	var seconds int64
	if err := json.Unmarshal(b, &seconds); err != nil {
		return errors.New("duration must be a Go duration string")
	}
	d.Duration = time.Duration(seconds) * time.Second
	return nil
}

func (d duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

type Config struct {
	ListenUDP        string   `json:"listen_udp"`
	ListenTCP        string   `json:"listen_tcp"`
	Database         string   `json:"database"`
	ServerPrivateKey string   `json:"server_private_key"`
	Obfuscation      string   `json:"obfuscation"`
	HandshakeTimeout duration `json:"handshake_timeout"`
	IdleTimeout      duration `json:"idle_timeout"`
	RekeyInterval    duration `json:"rekey_interval"`
	RekeyPackets     uint64   `json:"rekey_packets"`
	StatusListen     string   `json:"status_listen"`
	StatusToken      string   `json:"status_token"`
	LogLevel         string   `json:"log_level"`
	// AllowPrivateDestinations اجازه می‌دهد کاربران به شبکه‌های خصوصی
	// (10/8، 192.168/16 و …) وصل شوند. loopback و link-local همیشه مسدودند.
	AllowPrivateDestinations bool `json:"allow_private_destinations"`
}

func defaultConfig() Config {
	return Config{ListenUDP: ":443", ListenTCP: ":443", Database: "/var/lib/klink/klink.db",
		Obfuscation: "random", HandshakeTimeout: duration{30 * time.Second},
		IdleTimeout: duration{10 * time.Minute}, RekeyInterval: duration{15 * time.Minute},
		RekeyPackets: 1 << 20, StatusListen: "127.0.0.1:9091", LogLevel: "info"}
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
	if cfg.ListenUDP == "" && cfg.ListenTCP == "" {
		return cfg, errors.New("at least one of listen_udp or listen_tcp is required")
	}
	if len(cfg.StatusToken) < 32 {
		return cfg, errors.New("status_token is required and must contain at least 32 characters")
	}
	if host, _, err := net.SplitHostPort(cfg.StatusListen); err != nil {
		return cfg, fmt.Errorf("status_listen: %w", err)
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		// API وضعیت فهرست کاربران، IPها و مصرف را برمی‌گرداند و نباید عمومی باشد.
		return cfg, errors.New("status_listen must be a loopback address such as 127.0.0.1:9091")
	}
	return cfg, nil
}

func logger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

type PortStatus struct {
	Network   string `json:"network"`
	Address   string `json:"address"`
	Listening bool   `json:"listening"`
}

type coreStatus struct {
	session.Status
	Ports           []PortStatus `json:"ports"`
	ServerPublicKey string       `json:"server_public_key"`
	Obfuscation     string       `json:"obfuscation"`
	Version         string       `json:"version"`
}

func main() {
	configPath := flag.String("config", "/etc/klink/server.json", "path to server JSON configuration")
	genKey := flag.Bool("genkey", false, "generate a server X25519 key pair and exit")
	flag.Parse()
	if *genKey {
		key, err := kcrypto.GenerateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("private_key=%s\npublic_key=%s\n", key.PrivateBase64(), key.PublicBase64())
		return
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}
	log := logger(cfg.LogLevel)
	key, err := kcrypto.KeyFromBase64(cfg.ServerPrivateKey)
	if err != nil {
		log.Error("invalid server private key", "error", err)
		os.Exit(1)
	}
	profile, err := obfuscation.ByName(cfg.Obfuscation)
	if err != nil {
		log.Error("invalid obfuscation profile", "error", err)
		os.Exit(1)
	}
	db, err := store.Open(cfg.Database)
	if err != nil {
		log.Error("database open failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	manager, err := session.NewManager(session.Config{
		ServerKey: key, Store: db, Obfuscation: profile,
		HandshakeTimeout: cfg.HandshakeTimeout.Duration, IdleTimeout: cfg.IdleTimeout.Duration,
		RekeyInterval: cfg.RekeyInterval.Duration, RekeyPackets: cfg.RekeyPackets, Logger: log,
		OnSession: func(s *session.Session) {
			m := mux.NewWithPolicy(s, mux.Policy{AllowPrivate: cfg.AllowPrivateDestinations})
			s.SetHandlers(m.HandleFrame, m.Close)
		},
	})
	if err != nil {
		log.Error("session manager failed", "error", err)
		os.Exit(1)
	}
	defer manager.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listeners := make([]transport.Listener, 0, 2)
	ports := make([]PortStatus, 0, 2)
	errCh := make(chan error, 2)
	if cfg.ListenUDP != "" {
		l, err := transport.ListenUDP(cfg.ListenUDP)
		if err != nil {
			log.Error("UDP listen failed", "address", cfg.ListenUDP, "error", err)
			os.Exit(1)
		}
		listeners = append(listeners, l)
		ports = append(ports, PortStatus{Network: "udp", Address: l.LocalAddr().String(), Listening: true})
		log.Info("transport listening", "network", "udp", "address", l.LocalAddr().String())
		// پردازش موازی بسته‌های UDP؛ بسته‌های هر کلاینت به ترتیب در یک worker.
		go func() {
			err := l.Serve(runtime.GOMAXPROCS(0)*2, func(p transport.Packet) { manager.HandlePacket(l, p) })
			if ctx.Err() != nil || errors.Is(err, transport.ErrClosed) || errors.Is(err, net.ErrClosed) {
				err = nil
			}
			errCh <- err
		}()
	}
	if cfg.ListenTCP != "" {
		// هر اتصال TCP در goroutine خودش پردازش می‌شود.
		l, err := transport.ListenTCPHandler(cfg.ListenTCP, kcrypto.Prologue, manager.HandlePacket)
		if err != nil {
			log.Error("TCP listen failed", "address", cfg.ListenTCP, "error", err)
			os.Exit(1)
		}
		listeners = append(listeners, l)
		ports = append(ports, PortStatus{Network: "tcp", Address: l.LocalAddr().String(), Listening: true})
		log.Info("transport listening", "network", "tcp", "address", l.LocalAddr().String())
	}

	status := func() coreStatus {
		return coreStatus{Status: manager.Snapshot(), Ports: append([]PortStatus(nil), ports...),
			ServerPublicKey: key.PublicBase64(), Obfuscation: profile.Name(), Version: "1"}
	}
	statusServer := startStatusServer(cfg.StatusListen, cfg.StatusToken, status, log)
	defer statusServer.Shutdown(context.Background())

	log.Info("KLINK core started", "version", 1, "server_public_key", key.PublicBase64(), "obfuscation", profile.Name())
	select {
	case <-ctx.Done():
		log.Info("shutdown requested")
	case err := <-errCh:
		if err != nil {
			log.Error("transport stopped", "error", err)
		}
		stop()
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	manager.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = statusServer.Shutdown(shutdownCtx)
	log.Info("KLINK core stopped")
}

func startStatusServer(address, token string, status func() coreStatus, log *slog.Logger) *http.Server {
	muxHTTP := http.NewServeMux()
	muxHTTP.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	muxHTTP.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(status())
	})
	s := &http.Server{Addr: address, Handler: muxHTTP, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("status API stopped", "error", err)
		}
	}()
	return s
}
