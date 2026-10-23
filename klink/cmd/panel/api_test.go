package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kankipro/klink/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestAdminAndSubscriptionAPI(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "klink.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse-battery"), bcrypt.MinCost)
	cfg := defaultConfig()
	cfg.AdminPasswordHash = string(hash)
	cfg.CoreStatusToken = "status-token"
	cfg.ServerPublicKey = "server-public"
	cfg.UDPEndpoint = "vpn.example.com:443"
	cfg.TCPEndpoint = ""
	cfg.WebRoot = t.TempDir()
	a := newApp(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(a.routes())
	defer server.Close()
	a.cfg.PublicURL = server.URL
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	request := func(method, url string, body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-KLINK-Request", "1")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := request(http.MethodPost, server.URL+"/api/login", []byte(`{"username":"admin","password":"correct-horse-battery"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(http.MethodPost, server.URL+"/api/users", []byte(`{"name":"mobile","enabled":true,"volume_limit_gb":1.5,"device_limit":2}`))
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create %d %s", resp.StatusCode, b)
	}
	var user userView
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if user.VolumeLimit != 1610612736 || user.SubscriptionURL == "" {
		t.Fatalf("bad user %+v", user)
	}
	resp, err = http.Get(user.SubscriptionURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("subscription status %d", resp.StatusCode)
	}
	var subscription map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&subscription); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if subscription["client_private_key"] == "" || subscription["klink_version"] != float64(1) {
		t.Fatalf("bad subscription %+v", subscription)
	}
	resp = request(http.MethodPut, server.URL+"/api/users/1", []byte(`{"name":"mobile","enabled":false,"volume_limit_gb":1.5,"device_limit":2}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, err = http.Get(user.SubscriptionURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled subscription status %d", resp.StatusCode)
	}
}
