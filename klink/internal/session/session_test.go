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

type testClient struct {
	conn    *net.UDPConn
	profile obfuscation.Profile
	hello   [16]byte
}

func newTestClient(t *testing.T, server *net.UDPAddr, profile obfuscation.Profile) *testClient {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, server)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{conn: conn, profile: profile}
}

func (c *testClient) write(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := c.conn.Write(c.profile.Wrap(raw)); err != nil {
		t.Fatal(err)
	}
}

func (c *testClient) read(t *testing.T) []byte {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	n, err := c.conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.profile.Unwrap(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestUDPHandshakeDataRekeyReplayAndMigration(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "klink.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	clientKey, _ := kcrypto.GenerateKey()
	serverKey, _ := kcrypto.GenerateKey()
	u := &store.User{Name: "integration", PublicKey: base64.StdEncoding.EncodeToString(clientKey.Public[:]),
		Token: "token", Enabled: true, DeviceLimit: 1}
	if err := db.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	profile := obfuscation.Random{}
	listener, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 16)
	manager, err := NewManager(Config{ServerKey: serverKey, Store: db, Obfuscation: profile,
		HandshakeTimeout: 2 * time.Second, IdleTimeout: time.Minute, RekeyInterval: time.Hour,
		OnSession: func(s *Session) { s.SetHandlers(func(b []byte) { received <- append([]byte(nil), b...) }, nil) }})
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			p, err := listener.ReadPacket()
			if err != nil {
				return
			}
			manager.HandlePacket(listener, p)
		}
	}()

	client := newTestClient(t, listener.LocalAddr().(*net.UDPAddr), profile)
	defer client.conn.Close()
	hs, err := kcrypto.NewInitiator(clientKey, serverKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	hello := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	m1, _, _, _ := hs.WriteMessage(nil)
	raw1 := append([]byte{Version, msgHello1}, hello[:]...)
	client.write(t, append(raw1, m1...))
	raw2 := client.read(t)
	if len(raw2) <= 18 || raw2[1] != msgHello2 {
		t.Fatalf("unexpected handshake response %x", raw2)
	}
	if _, _, finished, err := hs.ReadMessage(raw2[18:]); err != nil || finished {
		t.Fatalf("msg2: %v", err)
	}
	m3, binding, finished, err := hs.WriteMessage(nil)
	if err != nil || !finished {
		t.Fatalf("msg3: %v", err)
	}
	raw3 := append([]byte{Version, msgHello3}, hello[:]...)
	client.write(t, append(raw3, m3...))
	ack := client.read(t)
	if len(ack) != 34 || ack[1] != msgHelloAck {
		t.Fatalf("unexpected ACK %x", ack)
	}
	var sid [16]byte
	copy(sid[:], ack[18:34])
	k1, _, err := kcrypto.ChannelKeys(binding)
	if err != nil {
		t.Fatal(err)
	}
	outbound, _ := kcrypto.NewChannel(k1)

	sendData := func(c *testClient, payload string) []byte {
		sealed, _, err := outbound.Seal([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		raw := append([]byte{Version, msgData}, sid[:]...)
		raw = append(raw, sealed...)
		c.write(t, raw)
		return c.profile.Wrap(raw)
	}
	sendData(client, "first")
	select {
	case b := <-received:
		if string(b) != "first" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first data not delivered")
	}
	outbound.Rekey()
	sendData(client, "after rekey")
	select {
	case b := <-received:
		if string(b) != "after rekey" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rekeyed data not delivered")
	}

	migrated := newTestClient(t, listener.LocalAddr().(*net.UDPAddr), profile)
	defer migrated.conn.Close()
	wire := sendData(migrated, "new network")
	select {
	case b := <-received:
		if string(b) != "new network" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("migrated data not delivered")
	}
	if _, err := migrated.conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-received:
		t.Fatalf("replayed packet delivered: %q", b)
	case <-time.After(150 * time.Millisecond):
	}
	status := manager.Snapshot()
	if status.OnlineUsers != 1 || status.OnlineSessions != 1 || len(status.Users) != 1 {
		t.Fatalf("bad status %+v", status)
	}
	if status.Users[0].Remote != migrated.conn.LocalAddr().String() {
		t.Fatalf("migration address not updated: %+v", status.Users[0])
	}

	manager.Close()
	listener.Close()
	<-readDone
	stored, err := db.GetUser(context.Background(), u.ID)
	if err != nil || stored.UsedBytes == 0 {
		t.Fatalf("usage not persisted: %+v %v", stored, err)
	}
}
