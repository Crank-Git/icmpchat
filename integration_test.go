package main

import (
	"strconv"
	"testing"
)

// simulateTransport models the bytes-on-the-wire path: encode a chunk, hand it
// to a receiver reassembler exactly as the listener's handlePacket would.
func simulateTransport(t *testing.T, rs *reassembler, m *Message, key []byte) (string, bool) {
	t.Helper()
	payload, err := encode(m, key)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(payload) > maxPayload {
		t.Fatalf("on-wire chunk %d is %d bytes, exceeds maxPayload %d", m.ChunkIdx, len(payload), maxPayload)
	}
	decoded, err := decode(payload, key)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rs.Add(decoded)
}

// TestIntegrationChunkedRoundTrip sends a long message one chunk at a time in
// order and out of order, then verifies full reassembly.
func TestIntegrationChunkedRoundTrip(t *testing.T) {
	key := newKey("integration-key")
	name := "carol"
	base := "integration test sentence that runs longer than a single 1000-byte " +
		"ICMP payload, so the encoder must split it into several chunks and the " +
		"receiver must reassemble those chunks in order using the shared id. "
	text := ""
	for i := 0; i < 8; i++ {
		text += base
	}

	chunks, cnt, err := chunkText(name, text, key)
	if err != nil {
		t.Fatalf("chunkText: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}

	rs := newReassembler()
	msgID := uint32(0xdeadbeef)

	// Deliver the last chunk first to prove order-independent reassembly.
	order := make([]int, len(chunks))
	for i := range order {
		order[i] = i
	}
	order[0] = len(chunks) - 1
	order[len(chunks)-1] = 0

	var got string
	for _, i := range order {
		m := &Message{Name: name, Text: string(chunks[i]), MsgID: msgID, ChunkIdx: uint8(i), ChunkCnt: cnt}
		out, complete := simulateTransport(t, rs, m, key)
		if complete {
			got = out
		}
	}
	if got != text {
		t.Fatalf("reassembled text mismatch:\n got %q\nwant %q", got, text)
	}
}

// TestIntegrationManyMessages sends several distinct messages back to back
// through the same reassembler to ensure message ids and fragments do not
// collide.
func TestIntegrationManyMessages(t *testing.T) {
	rs := newReassembler()
	const n = 25
	for i := 0; i < n; i++ {
		name := "u" + string(rune('a'+i%26))
		text := "message number" + strconv.Itoa(i)
		chunks, cnt, err := chunkText(name, text, nil)
		if err != nil {
			t.Fatalf("chunkText: %v", err)
		}
		msgID := uint32(1000 + i)
		var final string
		for j, c := range chunks {
			m := &Message{Name: name, Text: string(c), MsgID: msgID, ChunkIdx: uint8(j), ChunkCnt: cnt}
			out, complete := simulateTransport(t, rs, m, nil)
			if complete {
				final = out
			}
		}
		if final != text {
			t.Fatalf("message %d reassembled as %q, want %q", i, final, text)
		}
	}
}

// TestIntegrationCipherMismatchFails ensures a ciphertext produced with one key
// cannot be decoded by a receiver holding a different key.
func TestIntegrationCipherMismatchFails(t *testing.T) {
	senderKey := newKey("sender")
	receiverKey := newKey("receiver")

	m := &Message{Name: "d", Text: "secret payload", MsgID: 7, ChunkIdx: 0, ChunkCnt: 1}
	payload, err := encode(m, senderKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := decode(payload, receiverKey); err == nil {
		t.Fatalf("expected decode to fail with the wrong key")
	}
	// And the correct key must succeed.
	if _, err := decode(payload, senderKey); err != nil {
		t.Fatalf("decode with correct key failed: %v", err)
	}
}
