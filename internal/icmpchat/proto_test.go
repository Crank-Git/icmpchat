package icmpchat

import (
	"bytes"
	"testing"
)

func TestRoundTripCleartext(t *testing.T) {
	m := &Message{Name: "alice", Text: "hello world", MsgID: 0x01020304, ChunkIdx: 0, ChunkCnt: 1}
	payload, err := Encode(m, nil)
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
	chunks, cnt, err := ChunkText(name, string(text), nil, 0)
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
		payload, err := Encode(cm, nil)
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
	chunks, _, err := ChunkText(name, string(text), nil, 0)
	if err != nil {
		t.Fatalf("chunkText: %v", err)
	}
	for i, c := range chunks {
		cm := &Message{Name: name, Text: string(c), MsgID: 1, ChunkIdx: uint8(i), ChunkCnt: uint8(len(chunks))}
		payload, err := Encode(cm, nil)
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
	key := NewKey("correct horse")
	m := &Message{Name: "carol", Text: "secret payload", MsgID: 7, ChunkIdx: 0, ChunkCnt: 1}
	payload, err := Encode(m, key)
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
	payload, err := Encode(&Message{Name: "d", Text: "e", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, NewKey("right"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := decode(payload, NewKey("wrong")); err == nil {
		t.Fatalf("expected wrong-key decode to fail")
	}
}

func TestCleartextNotDecryptableWithKey(t *testing.T) {
	// A cleartext packet must not decode as ciphertext.
	payload, _ := Encode(&Message{Name: "f", Text: "g", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, nil)
	if _, err := decode(payload, NewKey("x")); err == nil {
		t.Fatalf("expected cleartext to fail decode under key")
	}
}

func TestNonceUniquePerEncode(t *testing.T) {
	key := NewKey("z")
	a, _ := Encode(&Message{Name: "h", Text: "i", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, key)
	b, _ := Encode(&Message{Name: "h", Text: "i", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, key)
	// Same header + nonce prefix, then ciphertext differs.
	if bytes.Equal(a, b) {
		t.Fatalf("two encodes produced identical payloads; nonce not random")
	}
}

// TestBuildPollHeader checks the poll header layout: magic, version, both the
// relay and poll flag bits, room length, and the room bytes.
func TestBuildPollHeader(t *testing.T) {
	h, err := BuildPollHeader("lobby")
	if err != nil {
		t.Fatalf("BuildPollHeader: %v", err)
	}
	if len(h) != relayHeaderBase+len("lobby") {
		t.Fatalf("header len = %d, want %d", len(h), relayHeaderBase+len("lobby"))
	}
	if string(h[0:4]) != magicStr {
		t.Fatalf("header magic = %q, want %q", h[0:4], magicStr)
	}
	if h[4] != protoVer {
		t.Fatalf("header ver = %d, want %d", h[4], protoVer)
	}
	if h[5]&(relayFlag|pollFlag) != (relayFlag | pollFlag) {
		t.Fatalf("header flag bits not set: 0x%02x", h[5])
	}
	if int(h[6]) != len("lobby") {
		t.Fatalf("header roomLen = %d, want %d", h[6], len("lobby"))
	}
	if string(h[7:]) != "lobby" {
		t.Fatalf("header room = %q, want %q", h[7:], "lobby")
	}
}

// TestBuildDeliverHeader checks the delivery header sets relayFlag|deliverFlag.
func TestBuildDeliverHeader(t *testing.T) {
	h, err := BuildDeliverHeader("lobby")
	if err != nil {
		t.Fatalf("BuildDeliverHeader: %v", err)
	}
	if h[5]&(relayFlag|deliverFlag) != (relayFlag | deliverFlag) {
		t.Fatalf("deliver header flag bits not set: 0x%02x", h[5])
	}
}

// TestParsePollRoundTrip verifies a built poll parses back to its room.
func TestParsePollRoundTrip(t *testing.T) {
	for _, room := range []string{"", "demo", "a-long-room-name-for-polls"} {
		h, err := BuildPollHeader(room)
		if err != nil {
			t.Fatalf("BuildPollHeader(%q): %v", room, err)
		}
		got, ok := ParsePoll(h)
		if !ok {
			t.Fatalf("ParsePoll(BuildPollHeader(%q)) ok=false", room)
		}
		if got != room {
			t.Fatalf("room = %q, want %q", got, room)
		}
	}
}

// TestParsePollRejectsTrailingBytes ensures a poll is exactly the relay header;
// any payload after it is a message, not a poll.
func TestParsePollRejectsTrailingBytes(t *testing.T) {
	h, _ := BuildPollHeader("demo")
	withExtra := append(append([]byte{}, h...), []byte("hi")...)
	if room, ok := ParsePoll(withExtra); ok || room == "demo" {
		t.Fatalf("poll with trailing bytes parsed as poll: room=%q", room)
	}
}

// TestParseDeliverRoundTrip verifies a delivery header plus inner chat payload
// parses back to the original chat payload.
func TestParseDeliverRoundTrip(t *testing.T) {
	room := "demo"
	h, err := BuildDeliverHeader(room)
	if err != nil {
		t.Fatalf("BuildDeliverHeader: %v", err)
	}
	chat := []byte("ICHT\x01\x00\x00\x00\x00\x00\x00\x00hi")
	wire := append(append([]byte{}, h...), chat...)
	got, ok := ParseDeliver(wire)
	if !ok {
		t.Fatalf("ParseDeliver: ok=false")
	}
	if !bytes.Equal(got, chat) {
		t.Fatalf("deliver payload = %q, want %q", got, chat)
	}
}

// TestPollAndDeliverAreDistinct ensures a poll is never parsed as a delivery and
// vice versa, so the two relay roles stay separable.
func TestPollAndDeliverAreDistinct(t *testing.T) {
	poll, _ := BuildPollHeader("demo")
	if _, ok := ParseDeliver(poll); ok {
		t.Fatalf("poll parsed as delivery")
	}
	deliver, _ := BuildDeliverHeader("demo")
	if _, ok := ParsePoll(deliver); ok {
		t.Fatalf("delivery parsed as poll")
	}
}

// TestParseDeliverRejectsPollBits makes sure a relay header carrying only the
// poll bit (no deliver bit) is not treated as a delivery.
func TestParseDeliverRejectsPollBits(t *testing.T) {
	h, _ := BuildPollHeader("demo")
	if _, ok := ParseDeliver(h); ok {
		t.Fatalf("poll header parsed as delivery")
	}
}
