package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestSenderLoopback verifies step 2: an unprivileged sender can deliver an
// echo request to 127.0.0.1 and receive the kernel's echo reply (delivery
// acknowledgment) without root.
func TestSenderLoopback(t *testing.T) {
	s, err := NewSender("127.0.0.1")
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	defer s.Close()

	payload := []byte("ICHT\x01\x00\x00\x00\x00\x00\x00\x00hello")
	if !s.Send(payload) {
		t.Fatalf("Send did not receive echo reply within timeout")
	}
	// Send() consumed the matching reply. Verify the reply carried our payload
	// by sending a second request and inspecting its reply directly.
	second := []byte("ICHT\x01\x00\x00\x00\x00\x00\x00\x00second")
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{Seq: nextSeq(), Data: second},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := s.conn.WriteTo(b, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.conn.SetReadDeadline(time.Now().Add(replyTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	rbuf := make([]byte, readBufferSize)
	n, _, err := s.conn.ReadFrom(rbuf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	rm, err := icmp.ParseMessage(1, rbuf[:n])
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	e, ok := rm.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("reply body is %T, not echo", rm.Body)
	}
	if !bytes.Equal(e.Data, second) {
		t.Fatalf("reply data = %q, want %q", e.Data, second)
	}
}
