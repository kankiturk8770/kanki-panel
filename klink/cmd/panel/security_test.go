package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kankipro/klink/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func newTestApp(t *testing.T) (*app, *httptest.Server) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "klink.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse-battery"), bcrypt.MinCost)
	cfg := defaultConfig()
	cfg.AdminPasswordHash = string(hash)
	cfg.CoreStatusToken = "status-token"
	cfg.ServerPublicKey = "server-public"
	cfg.UDPEndpoint = "vpn.example.com:443"
	cfg.WebRoot = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.WebRoot, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.WebRoot, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.WebRoot, ".env"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := newApp(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(a.routes())
	t.Cleanup(server.Close)
	return a, server
}

func login(t *testing.T, url, password string, header http.Header) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/api/login",
		bytes.NewReader([]byte(`{"username":"admin","password":"`+password+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KLINK-Request", "1")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Parallel guesses used to slip past the 5-attempt limit because attempts were
// counted only after bcrypt finished.
func TestParallelBruteForceIsLimited(t *testing.T) {
	_, server := newTestApp(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	checked := 0
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code := login(t, server.URL, "wrong-password-guess", nil); code == http.StatusUnauthorized {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if checked > loginBurst {
		t.Fatalf("%d passwords were checked in parallel; limit is %d", checked, loginBurst)
	}
	if code := login(t, server.URL, "correct-horse-battery", nil); code != http.StatusTooManyRequests {
		t.Fatalf("blocked IP could still log in: %d", code)
	}
}

func TestCrossOriginMutationRejected(t *testing.T) {
	_, server := newTestApp(t)
	h := http.Header{"Origin": {"https://evil.example"}}
	if code := login(t, server.URL, "correct-horse-battery", h); code != http.StatusForbidden {
		t.Fatalf("cross-origin login status %d", code)
	}
	h = http.Header{"Sec-Fetch-Site": {"cross-site"}}
	if code := login(t, server.URL, "correct-horse-battery", h); code != http.StatusForbidden {
		t.Fatalf("cross-site login status %d", code)
	}
	if code := login(t, server.URL, "correct-horse-battery", http.Header{"Origin": {server.URL}}); code != http.StatusOK {
		t.Fatalf("same-origin login status %d", code)
	}
}

func TestStaticFilesNoListingNoDotfiles(t *testing.T) {
	_, server := newTestApp(t)
	for path, want := range map[string]int{"/": 200, "/assets/": 404, "/.env": 404} {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
	}
	resp, _ := http.Get(server.URL + "/")
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); bytes.Contains([]byte(csp), []byte("cdn.")) {
		t.Fatalf("CSP still trusts a CDN: %s", csp)
	}
}

func TestConfigTLSValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "panel.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := `"admin_password_hash":"x","core_status_token":"t","server_public_key":"k","udp_endpoint":"h:443"`
	cfg, err := loadConfig(write(`{` + base + `,"acme_domain":"Panel.Example.com."}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACMEDomain != "panel.example.com" || !cfg.SecureCookies || cfg.ACMEHTTPListen != ":80" || cfg.ACMECacheDir == "" {
		t.Fatalf("ACME defaults not applied: %+v", cfg)
	}
	if _, err := loadConfig(write(`{` + base + `,"acme_domain":"203.0.113.7"}`)); err == nil {
		t.Fatal("IP address accepted as ACME domain")
	}
	if _, err := loadConfig(write(`{` + base + `,"tls_cert_file":"/x.crt"}`)); err == nil {
		t.Fatal("certificate without key accepted")
	}
}
