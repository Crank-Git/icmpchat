package main

import (
	"net"
	"testing"
	"time"

	"icmpchat/internal/icmpchat"
)

// TestRoomsAddAndMembers checks membership tracking and sender exclusion.
func TestRoomsAddAndMembers(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}}
	r.add("lobby", "10.0.0.1")
	r.add("lobby", "10.0.0.2")
	r.add("room-b", "10.0.0.3")

	got := r.memberIPs("lobby", "")
	if len(got) != 2 {
		t.Fatalf("memberIPs(lobby) = %v, want 2 members", got)
	}
	// Excluding one member leaves the other.
	only := r.memberIPs("lobby", "10.0.0.1")
	if len(only) != 1 || only[0] != "10.0.0.2" {
		t.Fatalf("memberIPs(lobby, exclude .1) = %v, want [10.0.0.2]", only)
	}
	// Rooms are independent.
	if len(r.memberIPs("room-b", "")) != 1 {
		t.Fatalf("room-b should have one member")
	}
}

// TestRoomsPrune verifies inactive members are dropped after the deadline and
// that a room with no members is removed entirely.
func TestRoomsPrune(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}}
	r.add("lobby", "10.0.0.1")
	r.add("lobby", "10.0.0.2")

	// Age one member beyond the deadline, keep the other fresh (in the future
	// so the prune's "now" cannot accidentally treat it as stale).
	r.mu.Lock()
	r.members["lobby"]["10.0.0.1"] = time.Now().Add(-2 * time.Hour)
	r.members["lobby"]["10.0.0.2"] = time.Now().Add(time.Minute)
	r.mu.Unlock()

	r.prune(time.Now())

	remaining := r.memberIPs("lobby", "")
	if len(remaining) != 1 || remaining[0] != "10.0.0.2" {
		t.Fatalf("after prune, lobby members = %v, want [10.0.0.2]", remaining)
	}

	// Age the last member, then prune again: the now-empty room is deleted.
	r.mu.Lock()
	r.members["lobby"]["10.0.0.2"] = time.Now().Add(-2 * time.Hour)
	r.mu.Unlock()
	r.prune(time.Now())
	if _, ok := r.members["lobby"]; ok {
		t.Fatalf("empty room lobby should be deleted")
	}
}

// TestRoute verifies relay parsing, membership recording, and target selection.
func TestRoute(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}}
	payload := makeRelayPayload(t, "lobby", "hi")

	room, chat, targets, ok := r.route("10.0.0.1", payload)
	if !ok {
		t.Fatalf("route(10.0.0.1) ok=false")
	}
	if room != "lobby" {
		t.Fatalf("room = %q, want lobby", room)
	}
	if len(chat) < 4 || string(chat[0:4]) != "ICHT" {
		t.Fatalf("chat payload = %q, want it to start with ICHT magic", chat)
	}
	if len(targets) != 0 {
		t.Fatalf("first sender has %d targets, want 0", len(targets))
	}

	// A second sender in the same room should be targeted by the first.
	_, _, targets, ok = r.route("10.0.0.2", payload)
	if !ok || len(targets) != 1 || targets[0] != "10.0.0.1" {
		t.Fatalf("second route targets = %v, want [10.0.0.1]", targets)
	}
}

// TestRouteRejectsNonRelay ensures plain and malformed payloads are rejected.
func TestRouteRejectsNonRelay(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}}

	// A plain (non-relay) chat message.
	plain, err := icmpchat.Encode(&icmpchat.Message{Name: "a", Text: "hi", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, _, _, ok := r.route("10.0.0.1", plain); ok {
		t.Fatalf("plain message should not route")
	}

	// Garbage that is not even our magic.
	if _, _, _, ok := r.route("10.0.0.1", []byte("nope")); ok {
		t.Fatalf("garbage should not route")
	}
}

// makeRelayPayload builds a relay-wrapped chat payload carrying text in room.
func makeRelayPayload(t *testing.T, room, text string) []byte {
	t.Helper()
	h, err := icmpchat.BuildRelayHeader(room)
	if err != nil {
		t.Fatalf("BuildRelayHeader: %v", err)
	}
	chat, err := icmpchat.Encode(&icmpchat.Message{Name: "n", Text: text, MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return append(append([]byte{}, h...), chat...)
}

// TestDetectLANIP should find at least one non-loopback address on a connected
// host, but never a loopback address.
func TestDetectLANIP(t *testing.T) {
	ip := detectLANIP()
	if ip == "" {
		t.Skip("no non-loopback IPv4 found (offline host?)")
	}
	if isLoopback(ip) {
		t.Fatalf("detectLANIP returned loopback %q", ip)
	}
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}
