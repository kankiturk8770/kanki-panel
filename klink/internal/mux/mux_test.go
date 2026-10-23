package mux

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type fakeSender struct{ frames chan []byte }

func (f *fakeSender) Send(frame []byte) error {
	f.frames <- append([]byte(nil), frame...)
	return nil
}

func receive(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case frame := <-ch:
		return frame
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for mux frame")
		return nil
	}
}

func TestTCPStream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Read(make([]byte, 5))
		_, _ = conn.Write([]byte("pong"))
	}()
	sender := &fakeSender{frames: make(chan []byte, 16)}
	m := NewWithPolicy(sender, Policy{AllowLoopback: true})
	defer m.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	open, _ := BuildOpen(7, NetworkTCP, "127.0.0.1", uint16(port))
	m.HandleFrame(open)
	status := receive(t, sender.frames)
	if id, code, err := ParseStatus(status); err != nil || id != 7 || code != StatusOK {
		t.Fatalf("status: %x %v", status, err)
	}
	m.HandleFrame(BuildData(7, []byte("hello")))
	data := receive(t, sender.frames)
	if data[0] != FrameData || binary.BigEndian.Uint32(data[1:5]) != 7 || !bytes.Equal(data[5:], []byte("pong")) {
		t.Fatalf("unexpected data: %x", data)
	}
}

func TestUDPAssociation(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 32)
		n, peer, err := conn.ReadFromUDP(buf)
		if err == nil {
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()
	sender := &fakeSender{frames: make(chan []byte, 16)}
	m := NewWithPolicy(sender, Policy{AllowLoopback: true})
	defer m.Close()
	open, _ := BuildOpen(9, NetworkUDP, "127.0.0.1", uint16(conn.LocalAddr().(*net.UDPAddr).Port))
	m.HandleFrame(open)
	if id, code, _ := ParseStatus(receive(t, sender.frames)); id != 9 || code != StatusOK {
		t.Fatal("UDP open failed")
	}
	m.HandleFrame(BuildData(9, []byte("datagram")))
	data := receive(t, sender.frames)
	if string(data[5:]) != "datagram" {
		t.Fatalf("unexpected UDP data %q", data[5:])
	}
}
