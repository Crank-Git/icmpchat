package main

import (
	"bytes"
	"testing"
)

func TestRoundTripCleartext(t *testing.T) {
	m := &Message{Name: "alice", Text: "hello world", MsgID: 0x01020304, ChunkIdx: 0, ChunkCnt: 1}
	payload, err := encode(m, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(payload) > maxPayload {
		t.Fatalf("payload %d exceeds max %d", len(payload), maxPayload)
	}
	got, err := decode(payload, nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if *got != *m {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, m)
	}
}

func TestChunking5000Bytes(t *testing.T) {
	name := "bob"
	text := make([]byte, 5000)
	for i := range text {
		text[i] = byte(i % 251)
	}
	chunks, cnt, err := chunkText(name, string(text), nil)
	if err != nil {
		t.Fatalf("chunkText: %v", err)
	}
	if cnt != uint8(len(chunks)) {
		t.Fatalf("chunk count mismatch: %d vs %d", cnt, len(chunks))
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	rs := newReassembler()
	var got string
	for i, c := range chunks {
		cm := &Message{Name: name, Text: string(c), MsgID: 42, ChunkIdx: uint8(i), ChunkCnt: uint8(len(chunks))}
		payload, err := encode(cm, nil)
		if err != nil {
			t.Fatalf("encode chunk: %v", err)
		}
		decoded, err := decode(payload, nil)
		if err != nil {
			t.Fatalf("decode chunk: %v", err)
		}
		out, complete := rs.Add(decoded)
		if complete {
			got = out
		}
	}
	if got != string(text) {
		t.Fatalf("reassembled text mismatch: got %d bytes, want %d", len(got), len(text))
	}
}

func TestChunkFitsWithinPayload(t *testing.T) {
	name := "x"
	text := make([]byte, 5000)
	chunks, _, err := chunkText(name, string(text), nil)
	if err != nil {
		t.Fatalf("chunkText: %v", err)
	}
	for i, c := range chunks {
		cm := &Message{Name: name, Text: string(c), MsgID: 1, ChunkIdx: uint8(i), ChunkCnt: uint8(len(chunks))}
		payload, err := encode(cm, nil)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if len(payload) > maxPayload {
			t.Fatalf("chunk %d payload %d exceeds max %d", i, len(payload), maxPayload)
		}
	}
}

func TestBadMagicRejected(t *testing.T) {
	_, err := decode([]byte("XXXX\x01\x00\x00\x00\x00\x00\x00\x00abc"), nil)
	if err != errBadMagic {
		t.Fatalf("want errBadMagic, got %v", err)
	}
}

func TestTruncatedRejected(t *testing.T) {
	// Too short to even hold the header.
	if _, err := decode([]byte("IC"), nil); err != errShort {
		t.Fatalf("want errShort for tiny packet, got %v", err)
	}
	// nameLen claims more name bytes than are present in the buffer.
	manual := append([]byte{}, magic...)
	manual = append(manual, protoVer)
	manual = append(manual, 0)          // flags
	manual = append(manual, 0, 0, 0, 1) // msgid
	manual = append(manual, 0)          // chunkIdx
	manual = append(manual, 1)          // chunkCnt
	manual = append(manual, 10)         // nameLen = 10
	manual = append(manual, 'a', 'b')   // only 2 name bytes present
	if _, err := decode(manual, nil); err != errShort {
		t.Fatalf("want errShort for truncated packet, got %v", err)
	}
}

func TestEncryptionRoundTrip(t *testing.T) {
	key := newKey("correct horse")
	m := &Message{Name: "carol", Text: "secret payload", MsgID: 7, ChunkIdx: 0, ChunkCnt: 1}
	payload, err := encode(m, key)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(payload) > maxPayload {
		t.Fatalf("encrypted payload %d exceeds max %d", len(payload), maxPayload)
	}
	got, err := decode(payload, key)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if *got != *m {
		t.Fatalf("encryption round trip mismatch:\n got %+v\nwant %+v", got, m)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	payload, err := encode(&Message{Name: "d", Text: "e", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, newKey("right"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := decode(payload, newKey("wrong")); err == nil {
		t.Fatalf("expected wrong-key decode to fail")
	}
}

func TestCleartextNotDecryptableWithKey(t *testing.T) {
	// A cleartext packet must not decode as ciphertext.
	payload, _ := encode(&Message{Name: "f", Text: "g", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, nil)
	if _, err := decode(payload, newKey("x")); err == nil {
		t.Fatalf("expected cleartext to fail decode under key")
	}
}

func TestNonceUniquePerEncode(t *testing.T) {
	key := newKey("z")
	a, _ := encode(&Message{Name: "h", Text: "i", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, key)
	b, _ := encode(&Message{Name: "h", Text: "i", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, key)
	// Same header + nonce prefix, then ciphertext differs.
	if bytes.Equal(a, b) {
		t.Fatalf("two encodes produced identical payloads; nonce not random")
	}
}
