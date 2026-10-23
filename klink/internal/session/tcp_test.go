package session

import (
	"context"
	"encoding/base64"
	"net"
	"path/filepath"
	"testing"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/obfuscation"
	"github.com/kankipro/klink/internal/store"
	"github.com/kankipro/klink/internal/transport"
)

func TestTCPHandshakeFramingUpgradeAndData(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "klink.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	clientKey, _ := kcrypto.GenerateKey()
	serverKey, _ := kcrypto.GenerateKey()
	u := &store.User{Name: "tcp", PublicKey: base64.StdEncoding.EncodeToString(clientKey.Public[:]), Token: "tcp-token", Enabled: true}
	if err := db.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	profile := obfuscation.Random{}
	listener, err := transport.ListenTCP("127.0.0.1:0", kcrypto.Prologue)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 2)
	manager, err := NewManager(Config{ServerKey: serverKey, Store: db, Obfuscation: profile, RekeyInterval: time.Hour,
		OnSession: func(s *Session) { s.SetHandlers(func(b []byte) { received <- b }, nil) }})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	go func() {
		for {
			p, err := listener.ReadPacket()
			if err != nil {
				return
			}
			manager.HandlePacket(listener, p)
		}
	}()

	conn, err := net.Dial("tcp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	framer := transport.NewFramer(kcrypto.Prologue)
	var reads uint64
	write := func(raw []byte) error { return framer.WriteFrame(conn, profile.Wrap(raw)) }
	read := func() ([]byte, error) {
		wrapped, err := framer.ReadFrame(conn, &reads)
		if err != nil {
			return nil, err
		}
		return profile.Unwrap(wrapped)
	}
	hs, _ := kcrypto.NewInitiator(clientKey, serverKey.Public)
	hello := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	m1, _, _, _ := hs.WriteMessage(nil)
	if err := write(append(append([]byte{Version, msgHello1}, hello[:]...), m1...)); err != nil {
		t.Fatal(err)
	}
	raw2, err := read()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hs.ReadMessage(raw2[18:]); err != nil {
		t.Fatal(err)
	}
	m3, secret, finished, err := hs.WriteMessage(nil)
	if err != nil || !finished {
		t.Fatal(err)
	}
	if err := write(append(append([]byte{Version, msgHello3}, hello[:]...), m3...)); err != nil {
		t.Fatal(err)
	}
	framer.Upgrade(secret)
	ack, err := read()
	if err != nil || len(ack) != 34 || ack[1] != msgHelloAck {
		t.Fatalf("ACK: %x %v", ack, err)
	}
	k1, _, _ := kcrypto.ChannelKeys(secret)
	outbound, _ := kcrypto.NewChannel(k1)
	sealed, _, _ := outbound.Seal([]byte("tcp payload"))
	raw := append(append([]byte{Version, msgData}, ack[18:34]...), sealed...)
	if err := write(raw); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-received:
		if string(payload) != "tcp payload" {
			t.Fatalf("got %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP data not delivered")
	}
}
