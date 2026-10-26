package icmpchat

import (
	"bytes"
	"testing"
)

// TestRelayHeaderLen checks the visible relay header length grows with the room.
func TestRelayHeaderLen(t *testing.T) {
	if got := RelayHeaderLen(""); got != relayHeaderBase {
		t.Fatalf("RelayHeaderLen(\"\") = %d, want %d", got, relayHeaderBase)
	}
	if got := RelayHeaderLen("lobby"); got != relayHeaderBase+len("lobby") {
		t.Fatalf("RelayHeaderLen(\"lobby\") = %d, want %d", got, relayHeaderBase+len("lobby"))
	}
}

// TestBuildRelayHeader verifies the header layout: magic, version, relay flag,
// room length, and the room bytes.
func TestBuildRelayHeader(t *testing.T) {
	h, err := BuildRelayHeader("lobby")
	if err != nil {
		t.Fatalf("BuildRelayHeader: %v", err)
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
	if h[5]&relayFlag == 0 {
		t.Fatalf("header flag bit not set: 0x%02x", h[5])
	}
	if int(h[6]) != len("lobby") {
		t.Fatalf("header roomLen = %d, want %d", h[6], len("lobby"))
	}
	if string(h[7:]) != "lobby" {
		t.Fatalf("header room = %q, want %q", h[7:], "lobby")
	}
}

// TestRelayRoomRejectsPlainMessage ensures a plain chat message is not mistaken
// for a relay header.
func TestRelayRoomRejectsPlainMessage(t *testing.T) {
	plain, err := Encode(&Message{Name: "a", Text: "hi", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, ok, _ := RelayRoom(plain); ok {
		t.Fatalf("RelayRoom(plain) ok=true, want ok=false")
	}
}

// TestSplitRelay confirms a relay message (header + chat payload) splits back
// into the original chat payload, which then decodes correctly.
func TestSplitRelay(t *testing.T) {
	room := "room-42"
	header, err := BuildRelayHeader(room)
	if err != nil {
		t.Fatalf("BuildRelayHeader: %v", err)
	}
	chat, err := Encode(&Message{Name: "bob", Text: "relayed", MsgID: 9, ChunkIdx: 0, ChunkCnt: 1}, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	msg := append(append([]byte{}, header...), chat...)

	gotRoom, ok, err := RelayRoom(msg)
	if err != nil || !ok {
		t.Fatalf("RelayRoom: (%q,%v,%v), want ok=true", gotRoom, ok, err)
	}
	if gotRoom != room {
		t.Fatalf("room = %q, want %q", gotRoom, room)
	}
	split, isRelay := splitRelay(msg)
	if !isRelay {
		t.Fatalf("splitRelay reported not a relay message")
	}
	if !bytes.Equal(split, chat) {
		t.Fatalf("split payload = %q, want %q", split, chat)
	}
	decoded, err := decode(split, nil)
	if err != nil {
		t.Fatalf("decode split: %v", err)
	}
	if decoded.Name != "bob" || decoded.Text != "relayed" {
		t.Fatalf("decoded = %+v, want bob/relayed", decoded)
	}
}

// TestRelayHeaderTooLong guards the 255-byte room limit.
func TestRelayHeaderTooLong(t *testing.T) {
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'r'
	}
	if _, err := BuildRelayHeader(string(long)); err != errRoomTooLong {
		t.Fatalf("want errRoomTooLong, got %v", err)
	}
}
