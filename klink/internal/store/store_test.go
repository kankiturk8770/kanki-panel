package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestUserLifecycleAndAuthorization(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "klink.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	u := &User{Name: "test", PublicKey: "public", PrivateKey: "private", Token: "token",
		Enabled: true, VolumeLimit: 1000, DeviceLimit: 2, ExpiresAt: &expires}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	authorized, err := s.Authorize(ctx, "public")
	if err != nil || authorized.ID != u.ID || authorized.ExpiresAt == nil {
		t.Fatalf("authorize: %+v %v", authorized, err)
	}
	if err := s.AddUsage(ctx, u.ID, 600); err != nil {
		t.Fatal(err)
	}
	authorized, _ = s.Authorize(ctx, "public")
	if authorized.UsedBytes != 600 {
		t.Fatalf("usage=%d", authorized.UsedBytes)
	}
	if err := s.AddUsage(ctx, u.ID, 400); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(ctx, "public"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("exhausted user authorized: %v", err)
	}
	if err := s.ResetUsage(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(ctx, "public"); err != nil {
		t.Fatal(err)
	}
	byToken, err := s.GetByToken(ctx, "token")
	if err != nil || byToken.PrivateKey != "private" {
		t.Fatalf("token lookup: %v", err)
	}
	if err := s.RotateToken(ctx, u.ID, "new-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetByToken(ctx, "token"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old token still works")
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted user found")
	}
}
