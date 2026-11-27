package main

import (
	"os"
	"testing"
)

// TestMain opens private destinations for this package's tests: the relay tests put their "game server" on the
// machine's own address, which on CI runners is a private one (10.x), closed to users since 3.68
func TestMain(m *testing.M) {
	if os.Getenv("KMIX_LAB_ALLOW_PRIVATE") == "" {
		if err := os.Setenv("KMIX_LAB_ALLOW_PRIVATE", "1"); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}
