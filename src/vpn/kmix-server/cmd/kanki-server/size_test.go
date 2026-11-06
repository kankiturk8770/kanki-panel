package main

import (
	"testing"

	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

// اپ کارت شبکه‌ی KANKI MIX را ۱۲۸۰ می‌گذارد (tunMTU)؛ پس بزرگ‌ترین UDP بازی ۱۲۵۲ بایت است.
const appTunMTU = 1280

// بسته‌ی KCP (ترافیک TCP) و بزرگ‌ترین UDP بازی در هر دو جهت داخل یک بسته‌ی obfs جا می‌شوند:
// هیچ‌چیز به خاطر اندازه دور ریخته نمی‌شود و هیچ‌چیز از سقف بزرگ‌تر فرستاده نمی‌شود.
func TestEverythingFitsOnePacket(t *testing.T) {
	if kcpMTU > obfs.MaxPayload {
		t.Fatalf("KCP %d > MaxPayload %d: KCP packets would be lost", kcpMTU, obfs.MaxPayload)
	}
	game := appTunMTU - 20 - 8
	if game+proto.DownHdrLen > obfs.MaxPayload {
		t.Fatalf("a %d-byte game datagram does not fit going down", game)
	}
	if game+proto.UpHdrLen > obfs.MaxPayload {
		t.Fatalf("a %d-byte game datagram does not fit going up", game)
	}
}
