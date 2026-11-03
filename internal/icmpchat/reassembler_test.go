package icmpchat

import (
	"testing"
	"time"
)

// chunkMsg is a small helper for building one chunk of a multi-chunk message.
func chunkMsg(id uint32, idx, cnt uint8, name, text string) *Message {
	return &Message{Name: name, Text: text, MsgID: id, ChunkIdx: idx, ChunkCnt: cnt}
}

// TestReassemblerEvictsStaleFragmentOnUnrelatedAdd proves the memory-leak fix:
// an incomplete fragment whose next chunk never arrives is evicted once the TTL
// passes, instead of being pinned in the map for the life of the process.
func TestReassemblerEvictsStaleFragmentOnUnrelatedAdd(t *testing.T) {
	rs := newReassembler()
	base := time.Now()
	cur := base
	rs.now = func() time.Time { return cur }

	// Chunk 0 of a 2-chunk message arrives; its sibling is lost.
	if _, done := rs.Add(chunkMsg(1, 0, 2, "a", "hello ")); done {
		t.Fatal("one of two chunks must not complete the message")
	}
	if _, ok := rs.frags[1]; !ok {
		t.Fatal("the partial message should be pending")
	}

	// The TTL elapses, then an unrelated message's chunk arrives.
	cur = base.Add(fragmentTTL + time.Second)
	rs.Add(chunkMsg(2, 0, 2, "b", "other "))

	if _, ok := rs.frags[1]; ok {
		t.Fatal("stale fragment for msg 1 should have been evicted after the TTL")
	}
	if _, ok := rs.frags[2]; !ok {
		t.Fatal("the fresh fragment for msg 2 should remain")
	}
}

// TestReassemblerStaleChunkDoesNotComplete verifies that a late chunk cannot
// resurrect and complete a message whose earlier chunks have already expired:
// the stale partial is dropped, so the late chunk only starts a fresh fragment.
func TestReassemblerStaleChunkDoesNotComplete(t *testing.T) {
	rs := newReassembler()
	base := time.Now()
	cur := base
	rs.now = func() time.Time { return cur }

	rs.Add(chunkMsg(7, 0, 2, "a", "hello "))

	// The second chunk arrives after the TTL; by then chunk 0 is gone.
	cur = base.Add(fragmentTTL + time.Second)
	out, done := rs.Add(chunkMsg(7, 1, 2, "a", "world"))
	if done {
		t.Fatalf("a chunk arriving after the TTL must not complete a stale message, got %q", out)
	}
	if len(rs.frags[7].chunks) != 1 {
		t.Fatalf("the late chunk should start a fresh single-chunk fragment, got %d chunks", len(rs.frags[7].chunks))
	}
}

// TestReassemblerCompletesWithinTTL is the positive control: chunks that arrive
// within the TTL still reassemble normally, so eviction does not break delivery.
func TestReassemblerCompletesWithinTTL(t *testing.T) {
	rs := newReassembler()
	base := time.Now()
	cur := base
	rs.now = func() time.Time { return cur }

	rs.Add(chunkMsg(9, 0, 2, "a", "hello "))
	cur = base.Add(fragmentTTL - time.Second) // still fresh
	out, done := rs.Add(chunkMsg(9, 1, 2, "a", "world"))
	if !done {
		t.Fatal("both chunks arrived within the TTL; the message should complete")
	}
	if out != "hello world" {
		t.Fatalf("reassembled text = %q, want %q", out, "hello world")
	}
	if len(rs.frags) != 0 {
		t.Fatalf("a completed message should leave no pending fragments, got %d", len(rs.frags))
	}
}
