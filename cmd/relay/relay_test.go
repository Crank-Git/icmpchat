package main

import (
	"fmt"
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
	r := &rooms{members: map[string]map[string]time.Time{}, queues: map[string]map[string][][]byte{}}
	payload := makeRelayPayload(t, "lobby", "hi")

	res := r.route("10.0.0.1", payload)
	if res.room != "lobby" || res.isPoll {
		t.Fatalf("route(10.0.0.1) = %+v, want room lobby, not a poll", res)
	}
	if len(res.chatPayload) < 4 || string(res.chatPayload[0:4]) != "ICHT" {
		t.Fatalf("chat payload = %q, want it to start with ICHT magic", res.chatPayload)
	}
	if len(res.targets) != 0 {
		t.Fatalf("first sender has %d targets, want 0", len(res.targets))
	}

	// A second sender in the same room should be targeted by the first.
	res = r.route("10.0.0.2", payload)
	if res.room != "lobby" || len(res.targets) != 1 || res.targets[0] != "10.0.0.1" {
		t.Fatalf("second route targets = %v, want [10.0.0.1]", res.targets)
	}
}

// TestRouteRejectsNonRelay ensures plain and malformed payloads are rejected.
func TestRouteRejectsNonRelay(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}, queues: map[string]map[string][][]byte{}}

	// A plain (non-relay) chat message.
	plain, err := icmpchat.Encode(&icmpchat.Message{Name: "a", Text: "hi", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if res := r.route("10.0.0.1", plain); res.room != "" {
		t.Fatalf("plain message should not route, got %+v", res)
	}

	// Garbage that is not even our magic.
	if res := r.route("10.0.0.1", []byte("nope")); res.room != "" {
		t.Fatalf("garbage should not route, got %+v", res)
	}
}

// TestRoutePoll ensures a poll is recognized as a poll and refreshes membership.
func TestRoutePoll(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}, queues: map[string]map[string][][]byte{}}
	poll := makePoll(t, "lobby")
	res := r.route("10.0.0.1", poll)
	if res.room != "lobby" || !res.isPoll {
		t.Fatalf("route(poll) = %+v, want room lobby, isPoll=true", res)
	}
	// The poller is now a member.
	if len(r.memberIPs("lobby", "")) != 1 {
		t.Fatalf("poller should be a member")
	}
}

// makePoll builds a poll payload: exactly the relay header with the poll bit.
func makePoll(t *testing.T, room string) []byte {
	t.Helper()
	h, err := icmpchat.BuildPollHeader(room)
	if err != nil {
		t.Fatalf("BuildPollHeader: %v", err)
	}
	return h
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

// TestQueueDrain verifies messages queue per member and drain in order, and that
// a second drain of the same member returns nothing.
func TestQueueDrain(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}, queues: map[string]map[string][][]byte{}}
	r.add("lobby", "10.0.0.1")
	r.queue("lobby", "10.0.0.1", []byte("ICHT1"))
	r.queue("lobby", "10.0.0.1", []byte("ICHT2"))

	got := r.drain("lobby", "10.0.0.1")
	if len(got) != 2 {
		t.Fatalf("drain returned %d messages, want 2", len(got))
	}
	if string(got[0]) != "ICHT1" || string(got[1]) != "ICHT2" {
		t.Fatalf("drain order = %q, %q, want ICHT1, ICHT2", got[0], got[1])
	}

	// A second drain returns nothing: each message is delivered once.
	if got := r.drain("lobby", "10.0.0.1"); len(got) != 0 {
		t.Fatalf("second drain returned %d messages, want 0", len(got))
	}
}

// TestQueueCapDropsOldest ensures the queue never exceeds maxQueue by dropping
// the oldest messages when it fills.
func TestQueueCapDropsOldest(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}, queues: map[string]map[string][][]byte{}}
	r.add("lobby", "10.0.0.1")
	const total = maxQueue + 10
	for i := 0; i < total; i++ {
		r.queue("lobby", "10.0.0.1", []byte(fmt.Sprintf("ICHT%d", i)))
	}

	got := r.drain("lobby", "10.0.0.1")
	if len(got) != maxQueue {
		t.Fatalf("drain returned %d messages, want cap %d", len(got), maxQueue)
	}
	// The oldest (ICHT0..ICHT9) should have been dropped; the first held is
	// ICHT10 (total - cap = 74 - 64).
	if string(got[0]) != fmt.Sprintf("ICHT%d", total-maxQueue) {
		t.Fatalf("first held message = %q, want ICHT%d (oldest dropped)", got[0], total-maxQueue)
	}
}

// TestPruneRemovesQueue ensures a pruned member's queue is cleared too, so it is
// not delivered after it has left the room.
func TestPruneRemovesQueue(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}, queues: map[string]map[string][][]byte{}}
	r.add("lobby", "10.0.0.1")
	r.queue("lobby", "10.0.0.1", []byte("ICHT1"))

	// Prune everything: the member is now inactive.
	r.prune(time.Now())

	if r.members["lobby"] != nil {
		t.Fatalf("member should have been pruned")
	}
	if got := r.drain("lobby", "10.0.0.1"); len(got) != 0 {
		t.Fatalf("pruned member still has %d queued messages, want 0", len(got))
	}
}

// TestRouteRejectsDeliveryEchoBack is the regression test for a relay feedback
// loop: when the relay delivers a message as an echo reply (type 0), the
// receiver's kernel auto-acks it by sending an echo request back carrying the
// deliver bit. That echo-back must not be re-forwarded to other members.
func TestRouteRejectsDeliveryEchoBack(t *testing.T) {
	r := &rooms{members: map[string]map[string]time.Time{}, queues: map[string]map[string][][]byte{}}
	header, err := icmpchat.BuildDeliverHeader("lobby")
	if err != nil {
		t.Fatalf("BuildDeliverHeader: %v", err)
	}
	chat, err := icmpchat.Encode(&icmpchat.Message{Name: "x", Text: "y", MsgID: 1, ChunkIdx: 0, ChunkCnt: 1}, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	echoBack := append(append([]byte{}, header...), chat...)

	res := r.route("10.0.0.2", echoBack)
	if res.room != "" || res.isPoll || res.chatPayload != nil {
		t.Fatalf("delivery echo-back routed: %+v, want empty", res)
	}
	// The echo-back must not have registered its sender as a member either.
	if len(r.memberIPs("lobby", "")) != 0 {
		t.Fatalf("echo-back sender should not be a member")
	}
}
