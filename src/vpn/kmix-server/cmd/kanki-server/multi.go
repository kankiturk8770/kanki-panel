package main

// حالت چندکاربره (برای پنل): kanki-server -users users.json -api 127.0.0.1:PORT -api-secret S
//
// users.json:
//
//	{"users": [{"name": "ali", "key": "<hex 64>", "max": 2}, ...]}
//
// max = حداکثر دستگاه هم‌زمان (۰ = نامحدود). فایل با SIGHUP یا POST /reload دوباره خوانده می‌شود.
//
// API (فقط روی 127.0.0.1، هدر Authorization: secret؛ همان شکل API آمار Hysteria2):
//
//	GET  /traffic?clear=1   {"ali": {"tx": 123, "rx": 456}}   بایت روی سیم از آخرین clear
//	GET  /online            {"ali": 1}                        دستگاه‌های فعال (۳۰ ثانیه‌ی اخیر)
//	POST /reload            فایل کاربران دوباره خوانده می‌شود

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"kanki-tunnel/internal/obfs"
)

const (
	sessionAlive = 30 * time.Second
	// دستگاه فعال هر ثانیه پینگ می‌فرستد؛ نشستی که این‌قدر ساکت است بسته شده (اپ بسته/باز شد)
	// و وقتی کاربر به سقف رسیده جایش را به دستگاه تازه می‌دهد
	sessionGone = 5 * time.Second
)

type usersFile struct {
	Users []struct {
		Name string `json:"name"`
		Key  string `json:"key"`
		Max  int    `json:"max"`
	} `json:"users"`
}

// sessions دستگاه‌های فعال هر کاربر را از روی شناسه‌ی نشستی که در پینگ و بسته‌های UDP می‌آید می‌شمارد.
type sessions struct {
	mu     sync.Mutex
	limits map[string]int
	seen   map[string]map[uint64]time.Time
}

var userSessions = &sessions{limits: map[string]int{}, seen: map[string]map[uint64]time.Time{}}

// allow نشست sid از کاربر name را ثبت می‌کند؛ false یعنی کاربر به سقف دستگاه رسیده.
func (s *sessions) allow(name string, sid uint64) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.seen[name]
	if m == nil {
		m = map[uint64]time.Time{}
		s.seen[name] = m
	}
	if _, ok := m[sid]; !ok {
		if max := s.limits[name]; max > 0 {
			live := 0
			for id, t := range m {
				if now.Sub(t) < sessionAlive {
					live++
				} else {
					delete(m, id)
				}
			}
			if live >= max {
				for id, t := range m {
					if now.Sub(t) >= sessionGone {
						delete(m, id)
						live--
					}
				}
			}
			if live >= max {
				return false
			}
		}
	}
	m[sid] = now
	return true
}

func (s *sessions) online() map[string]int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for name, m := range s.seen {
		for id, t := range m {
			if now.Sub(t) < sessionGone {
				out[name]++
			} else if now.Sub(t) < sessionAlive {
				// ساکت ولی هنوز پاک نشده: آنلاین شمرده نمی‌شود
			} else {
				delete(m, id)
			}
		}
		if len(m) == 0 {
			delete(s.seen, name)
		}
	}
	return out
}

func loadUsers(ring *obfs.Keyring, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f usersFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	keys := map[string]string{}
	limits := map[string]int{}
	for _, u := range f.Users {
		keys[u.Key] = u.Name
		limits[u.Name] = u.Max
	}
	if err := ring.Set(keys); err != nil {
		return err
	}
	userSessions.mu.Lock()
	userSessions.limits = limits
	for name := range userSessions.seen {
		if _, ok := limits[name]; !ok {
			delete(userSessions.seen, name)
		}
	}
	userSessions.mu.Unlock()
	log.Printf("[kanki-server] %d کاربر بارگذاری شد", ring.Len())
	return nil
}

// watchUsers با SIGHUP فایل کاربران را دوباره می‌خواند.
func watchUsers(ring *obfs.Keyring, path string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		if err := loadUsers(ring, path); err != nil {
			log.Printf("خواندن کاربران: %v", err)
		}
	}
}

func serveAPI(addr, secret string, ring *obfs.Keyring, usersPath string) {
	authed := func(r *http.Request) bool {
		return secret != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(secret)) == 1
	}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		out := map[string]map[string]int64{}
		for name, t := range ring.Traffic(r.URL.Query().Get("clear") == "1") {
			out[name] = map[string]int64{"rx": t[0], "tx": t[1]}
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/online", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, userSessions.online())
	})
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) || r.Method != http.MethodPost {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := loadUsers(ring, usersPath); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "users": ring.Len()})
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
