package transport

import (
	"bytes"
	"net"
	"testing"
)

func TestFramerSequence(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	writer, reader := NewFramer([]byte("seed")), NewFramer([]byte("seed"))
	var reads uint64
	for i, size := range []int{1, 255, 256, 4096, 65535} {
		if i == 2 {
			binding := []byte("authenticated channel binding")
			writer.Upgrade(binding)
			reader.Upgrade(binding)
		}
		payload := bytes.Repeat([]byte{byte(i + 1)}, size)
		errCh := make(chan error, 1)
		go func() { errCh <- writer.WriteFrame(left, payload) }()
		decoded, err := reader.ReadFrame(right, &reads)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("payload mismatch at frame %d", i)
		}
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}
