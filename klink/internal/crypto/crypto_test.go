package crypto

import (
	"bytes"
	"testing"
)

func completeHandshake(t *testing.T) (clientIn, clientOut, serverIn, serverOut *Channel, binding []byte) {
	t.Helper()
	clientKey, _ := GenerateKey()
	serverKey, _ := GenerateKey()
	client, err := NewInitiator(clientKey, serverKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewResponder(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	m1, _, finished, err := client.WriteMessage(nil)
	if err != nil || finished {
		t.Fatalf("message 1: %v", err)
	}
	if _, _, finished, err = server.ReadMessage(m1); err != nil || finished {
		t.Fatalf("read 1: %v", err)
	}
	m2, _, finished, err := server.WriteMessage(nil)
	if err != nil || finished {
		t.Fatalf("message 2: %v", err)
	}
	if _, _, finished, err = client.ReadMessage(m2); err != nil || finished {
		t.Fatalf("read 2: %v", err)
	}
	m3, clientBinding, finished, err := client.WriteMessage(nil)
	if err != nil || !finished {
		t.Fatalf("message 3: %v", err)
	}
	_, serverBinding, finished, err := server.ReadMessage(m3)
	if err != nil || !finished {
		t.Fatalf("read 3: %v", err)
	}
	if !bytes.Equal(clientBinding, serverBinding) {
		t.Fatal("channel bindings differ")
	}
	if !bytes.Equal(server.PeerStatic(), clientKey.Public[:]) {
		t.Fatal("wrong authenticated client static key")
	}
	k1, k2, err := ChannelKeys(clientBinding)
	if err != nil {
		t.Fatal(err)
	}
	clientOut, _ = NewChannel(k1)
	serverIn, _ = NewChannel(k1)
	serverOut, _ = NewChannel(k2)
	clientIn, _ = NewChannel(k2)
	return clientIn, clientOut, serverIn, serverOut, clientBinding
}

func TestNoiseXKAndBidirectionalChannels(t *testing.T) {
	clientIn, clientOut, serverIn, serverOut, _ := completeHandshake(t)
	for i := 0; i < 100; i++ {
		message := bytes.Repeat([]byte{byte(i)}, i*7)
		sealed, seq, err := clientOut.Seal(message)
		if err != nil || seq != uint64(i+1) {
			t.Fatalf("seal: %v seq=%d", err, seq)
		}
		plain, _, epoch, err := serverIn.Open(sealed)
		if err != nil || epoch != 0 || !bytes.Equal(plain, message) {
			t.Fatalf("open: %v", err)
		}
		reply, _, _ := serverOut.Seal(plain)
		decoded, _, _, err := clientIn.Open(reply)
		if err != nil || !bytes.Equal(decoded, message) {
			t.Fatalf("reply: %v", err)
		}
	}
}

func TestRekeyAndTamperedEpochCannotPoisonReceiver(t *testing.T) {
	_, clientOut, serverIn, _, _ := completeHandshake(t)
	first, _, _ := clientOut.Seal([]byte("epoch zero"))
	if _, _, _, err := serverIn.Open(first); err != nil {
		t.Fatal(err)
	}
	clientOut.Rekey()
	bad, _, _ := clientOut.Seal([]byte("bad"))
	bad[len(bad)-1] ^= 1
	if _, _, _, err := serverIn.Open(bad); err == nil {
		t.Fatal("tampered packet accepted")
	}
	good, seq, _ := clientOut.Seal([]byte("epoch one"))
	plain, gotSeq, epoch, err := serverIn.Open(good)
	if err != nil || gotSeq != seq || epoch != 1 || string(plain) != "epoch one" {
		t.Fatalf("valid rekey packet rejected after forgery: %v", err)
	}
}

func TestReplayWindow(t *testing.T) {
	var w ReplayWindow
	if err := w.Check(100); err != nil {
		t.Fatal(err)
	}
	if err := w.Check(99); err != nil {
		t.Fatal(err)
	}
	if err := w.Check(100); err != ErrReplay {
		t.Fatalf("duplicate accepted: %v", err)
	}
	if err := w.Check(1100); err != nil {
		t.Fatal(err)
	}
	if err := w.Check(1); err != ErrReplay {
		t.Fatalf("old packet accepted: %v", err)
	}
	w.Reset()
	if err := w.Check(1); err != nil {
		t.Fatalf("sequence after epoch reset rejected: %v", err)
	}
}
