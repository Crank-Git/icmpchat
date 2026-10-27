package icmpchat

import (
	"bytes"
	"testing"
)

// buildIPv4Packet wraps an ICMP payload in a minimal 20-byte IPv4 header with
// IHL=5, so we can exercise stripIPHeader without a real socket.
func buildIPv4Packet(icmpPayload []byte, ihl uint8) []byte {
	hdr := make([]byte, int(ihl)*4)
	hdr[0] = 0x40 | (ihl & 0x0f) // version 4 + IHL
	return append(hdr, icmpPayload...)
}

func TestStripIPHeaderStandard(t *testing.T) {
	payload := []byte("ICHT\x01\x00\x00\x00\x00\x00\x00\x00hi")
	pkt := buildIPv4Packet(payload, 5)
	got, err := stripIPHeader(pkt)
	if err != nil {
		t.Fatalf("stripIPHeader: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("stripped = %q, want %q", got, payload)
	}
}

func TestStripIPHeaderWithOptions(t *testing.T) {
	// IHL=9 => 36-byte header (20 bytes + 16 bytes of options).
	payload := []byte("ICHT\x01\x00\x00\x00\x00\x00\x00\x00hi")
	pkt := buildIPv4Packet(payload, 9)
	got, err := stripIPHeader(pkt)
	if err != nil {
		t.Fatalf("stripIPHeader: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("stripped len = %d, want %d", len(got), len(payload))
	}
}

func TestStripIPHeaderRejects(t *testing.T) {
	if _, err := stripIPHeader([]byte{0x45, 0, 0}); err == nil {
		t.Fatalf("expected error for packet shorter than IP header")
	}
	// A 20-byte buffer that declares IHL=15 (60 bytes): the claim exceeds the
	// actual length, so it must be rejected.
	bad := make([]byte, 20)
	bad[0] = 0x40 | 0x0f
	if _, err := stripIPHeader(bad); err == nil {
		t.Fatalf("expected error for bogus IHL")
	}
}

// TestStripIPHeaderShortHeaderless ensures a headerless ICMP message shorter
// than a full IPv4 header is passed through, not rejected. Kernels deliver raw
// ICMP to ip4:icmp sockets without the leading IPv4 header, and a relay poll is
// only 19 bytes (8-byte ICMP header + 11-byte relay header); the old code's
// `len < 20` guard dropped it before the version nibble could be checked.
func TestStripIPHeaderShortHeaderless(t *testing.T) {
	// 8-byte ICMP echo-request header (type 0x08) + 11-byte relay poll header:
	// 49 43 48 54 ("ICHT") 01 (ver) 03 (relay|poll flags) 04 (room len) 64 ("d").
	poll := []byte{0x08, 0x00, 0x8c, 0x7d, 0x00, 0x15, 0x00, 0x01, 0x49, 0x43, 0x48, 0x54, 0x01, 0x03, 0x04, 0x64}
	got, err := stripIPHeader(poll)
	if err != nil {
		t.Fatalf("stripIPHeader short headerless: %v", err)
	}
	if !bytes.Equal(got, poll) {
		t.Fatalf("stripped = %x, want %x", got, poll)
	}

	// The very shortest headerless ICMP echo request is an 8-byte header with no
	// data; it must also pass through rather than being dropped as too short.
	echo := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	got, err = stripIPHeader(echo)
	if err != nil {
		t.Fatalf("stripIPHeader 8-byte headerless: %v", err)
	}
	if len(got) != len(echo) {
		t.Fatalf("stripped len = %d, want %d", len(got), len(echo))
	}
}
