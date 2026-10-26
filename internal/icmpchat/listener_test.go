package icmpchat

import (
	"bytes"
	"net"
	"testing"
)

// echoRequestPacket wraps an ICMP echo request (type 8) carrying data in a
// minimal 20-byte IPv4 header, mimicking what a raw socket delivers.
func echoRequestPacket(data []byte) []byte {
	icmpBody := make([]byte, 8+len(data))
	icmpBody[0] = 8 // echo request
	icmpBody[4] = 0
	icmpBody[5] = 0 // identifier
	icmpBody[6] = 0
	icmpBody[7] = 0 // sequence
	copy(icmpBody[8:], data)
	return buildIPv4Packet(icmpBody, 5)
}

// echoReplyPacket wraps an ICMP echo reply (type 0).
func echoReplyPacket(data []byte) []byte {
	icmpBody := make([]byte, 8+len(data))
	icmpBody[0] = 0 // echo reply
	copy(icmpBody[8:], data)
	return buildIPv4Packet(icmpBody, 5)
}

func newTestListener(key []byte) *Listener {
	return &Listener{peer: "127.0.0.1", key: key, reasm: newReassembler()}
}

func TestHandleEchoRequest(t *testing.T) {
	l := newTestListener(nil)
	msg := &Message{Name: "alice", Text: "ping", MsgID: 11, ChunkIdx: 0, ChunkCnt: 1}
	payload, _ := Encode(msg, nil)
	pkt := echoRequestPacket(payload)

	name, text, complete, dropped, err := l.handlePacket(net.ParseIP("127.0.0.1"), pkt)
	if err != nil {
		t.Fatalf("handlePacket err: %v", err)
	}
	if dropped {
		t.Fatalf("echo request should not be dropped")
	}
	if !complete || name != "alice" || text != "ping" {
		t.Fatalf("got name=%q text=%q complete=%v, want alice/ping/true", name, text, complete)
	}
}

func TestHandleEchoReplyDropped(t *testing.T) {
	l := newTestListener(nil)
	pkt := echoReplyPacket([]byte("ICHT\x01\x00\x00\x00\x00\x00\x00\x00x"))
	_, _, complete, dropped, err := l.handlePacket(net.ParseIP("127.0.0.1"), pkt)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !dropped || complete {
		t.Fatalf("echo reply should be dropped, got complete=%v", complete)
	}
}

func TestHandleWrongSourceDropped(t *testing.T) {
	l := newTestListener(nil)
	msg := &Message{Name: "eve", Text: "spoof", MsgID: 2, ChunkIdx: 0, ChunkCnt: 1}
	payload, _ := Encode(msg, nil)
	pkt := echoRequestPacket(payload)
	_, _, complete, dropped, _ := l.handlePacket(net.ParseIP("10.0.0.9"), pkt)
	if !dropped || complete {
		t.Fatalf("off-peer packet should be dropped")
	}
}

func TestHandleBadMagicDropped(t *testing.T) {
	l := newTestListener(nil)
	pkt := echoRequestPacket([]byte("XXXX\x01\x00\x00\x00\x00\x00\x00\x00x"))
	_, _, complete, dropped, _ := l.handlePacket(net.ParseIP("127.0.0.1"), pkt)
	if !dropped || complete {
		t.Fatalf("bad-magic packet should be dropped")
	}
}

func TestHandleChunkReassembly(t *testing.T) {
	l := newTestListener(nil)
	name := "bob"
	// ~3000 bytes forces several 1000-byte chunks.
	base := "the quick brown fox jumps over the lazy dog "
	text := ""
	for i := 0; i < 40; i++ {
		text += base
	} // ~1720 bytes -> several chunks

	chunks, cnt, err := ChunkText(name, text, nil, 0)
	if cnt < 2 {
		t.Fatalf("expected multiple chunks, got %d", cnt)
	}
	if err != nil {
		t.Fatalf("chunkText: %v", err)
	}
	msgID := uint32(99)
	var received string
	for i, c := range chunks {
		cm := &Message{Name: name, Text: string(c), MsgID: msgID, ChunkIdx: uint8(i), ChunkCnt: cnt}
		payload, _ := Encode(cm, nil)
		pkt := echoRequestPacket(payload)
		gotName, gotText, complete, dropped, err := l.handlePacket(net.ParseIP("127.0.0.1"), pkt)
		if err != nil {
			t.Fatalf("handlePacket: %v", err)
		}
		if dropped {
			t.Fatalf("chunk %d dropped", i)
		}
		if complete {
			received = gotName + "\x00" + gotText
		}
	}
	if received != name+"\x00"+text {
		t.Fatalf("reassembled mismatch: got %q", received)
	}
}

func TestHandleEncryptedCorrectKey(t *testing.T) {
	key := NewKey("s3cret")
	l := newTestListener(key)
	msg := &Message{Name: "carol", Text: "secret text", MsgID: 5, ChunkIdx: 0, ChunkCnt: 1}
	payload, _ := Encode(msg, key)
	pkt := echoRequestPacket(payload)
	name, text, complete, dropped, err := l.handlePacket(net.ParseIP("127.0.0.1"), pkt)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dropped || !complete || name != "carol" || text != "secret text" {
		t.Fatalf("correct-key decrypt failed: name=%q text=%q complete=%v", name, text, complete)
	}
}

func TestHandleEncryptedWrongKeyDropped(t *testing.T) {
	l := newTestListener(NewKey("wrong"))
	msg := &Message{Name: "carol", Text: "secret text", MsgID: 6, ChunkIdx: 0, ChunkCnt: 1}
	payload, _ := Encode(msg, NewKey("right"))
	pkt := echoRequestPacket(payload)
	_, _, complete, dropped, _ := l.handlePacket(net.ParseIP("127.0.0.1"), pkt)
	if !dropped || complete {
		t.Fatalf("wrong-key ciphertext should be dropped")
	}
}

// echoRequestRaw builds the ICMP bytes for an echo request (type 8) as the
// kernel delivers them after the IPv4 header is stripped: type, code, checksum,
// identifier, sequence, then data. The checksum is left zero, which ParseMessage
// does not verify.
func echoRequestRaw(data []byte) []byte {
	b := make([]byte, 8+len(data))
	b[0] = 8 // echo request
	copy(b[8:], data)
	return b
}

// echoReplyRaw builds the ICMP bytes for an echo reply (type 0).
func echoReplyRaw(data []byte) []byte {
	b := make([]byte, 8+len(data))
	b[0] = 0 // echo reply
	copy(b[8:], data)
	return b
}

// TestParseEchoRequestRejectsEchoReplies is the regression test for a relay
// forwarding loop: parseEchoRequest must accept echo requests (type 8) but
// reject echo replies (type 0), which are the kernel's auto-acks of our own
// forwards. Accepting replies let the relay re-forward its own output forever.
func TestParseEchoRequestRejectsEchoReplies(t *testing.T) {
	req := echoRequestRaw([]byte("ICHT\x01\x00\x00\x00\x00\x00\x00\x00hi"))
	payload, ok := parseEchoRequest(req)
	if !ok {
		t.Fatalf("echo request rejected")
	}
	if !bytes.HasPrefix(payload, []byte("ICHT")) {
		t.Fatalf("payload = %q, want it to start with ICHT magic", payload)
	}

	// An echo reply must be rejected (this is what previously looped).
	if _, ok := parseEchoRequest(echoReplyRaw([]byte("ICHT\x01\x00\x00\x00\x00\x00\x00\x00hi"))); ok {
		t.Fatalf("echo reply should be rejected")
	}

	// Garbage / non-ICMP bytes must be rejected too.
	if _, ok := parseEchoRequest([]byte{0xff, 0xff, 0xff}); ok {
		t.Fatalf("garbage should be rejected")
	}
}
