package obfuscation

import (
	"bytes"
	"testing"
)

func TestProfilesRoundTrip(t *testing.T) {
	for _, name := range []string{"random", "tls-mimic"} {
		profile, err := ByName(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{1, 34, 1200, 20000, 65500} {
			packet := bytes.Repeat([]byte{byte(size)}, size)
			wrapped := profile.Wrap(packet)
			plain, err := profile.Unwrap(wrapped)
			if err != nil || !bytes.Equal(plain, packet) {
				t.Fatalf("%s size=%d: %v", name, size, err)
			}
		}
	}
}

func TestTLSMimicRejectsMalformedRecords(t *testing.T) {
	p := TLSMimic{}
	cases := [][]byte{nil, {0x17}, {0x16, 3, 3, 0, 1, 1}, {0x17, 3, 3, 0, 0}, {0x17, 3, 3, 0, 2, 1}}
	for _, packet := range cases {
		if _, err := p.Unwrap(packet); err == nil {
			t.Fatalf("accepted malformed packet %x", packet)
		}
	}
}
