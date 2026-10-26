package main

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// isICMPPermissionErr reports whether err indicates that an ICMP socket could
// not be opened because of missing privileges or capabilities (EPERM/EACCES),
// including the platform-specific wording used on macOS and Linux.
func isICMPPermissionErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "permission denied") ||
		strings.Contains(low, "operation not permitted") ||
		strings.Contains(low, "not permitted") ||
		strings.Contains(low, "operation not allowed")
}

// TestSenderLoopback verifies step 2: an unprivileged sender can deliver an
// echo request to 127.0.0.1 and receive the kernel's echo reply (delivery
// acknowledgment) without root.
func TestSenderLoopback(t *testing.T) {
	s, err := NewSender("127.0.0.1")
	if err != nil {
		// Opening an ICMP socket needs CAP_NET_RAW. Skip where the environment
		// (e.g. a locked-down CI runner) denies it, rather than failing.
		if isICMPPermissionErr(err) {
			t.Skipf("ICMP sender socket unavailable: %v", err)
		}
		t.Fatalf("NewSender: %v", err)
	}
	defer s.Close()

	if s.raw {
		// The raw fallback needs root and uses a divergent send path (net.IPAddr
		// destination); it is exercised by the e2e binary test instead of this
		// unprivileged-socket check.
		t.Skip("raw sender fallback; covered by the e2e binary test")
	}

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
