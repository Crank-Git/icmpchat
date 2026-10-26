package main

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
