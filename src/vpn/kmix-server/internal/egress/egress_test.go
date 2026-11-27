package egress

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestLocalAndPrivateAreBlocked(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.8.9.1", "::1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "224.0.0.1"} {
		if Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "172.32.0.1"} {
		if !Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
}

func TestDialRefusesLoopbackByNameAndAddress(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "::1", "169.254.169.254"} {
		if _, err := DialTCP(context.Background(), h, 8080, time.Second); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: %v", h, err)
		}
	}
}
