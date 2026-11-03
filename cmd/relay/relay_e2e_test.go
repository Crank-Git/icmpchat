package main

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"icmpchat/internal/icmpchat"
)

// relayE2EIP is the loopback address the relay and clients use. A and B share
// it because a single-host test cannot hold distinct routable source IPs on
// every platform; target *selection* (excluding the sender) is covered by the
// routing unit tests, so these tests queue for the poller directly and focus on
// the socket wire path that no other test exercises.
const relayE2EIP = "127.0.0.1"

// encodeChunks returns the chat payloads a relay client produces for one
// message: each chunk Encoded (optionally sealed), sized so that a relay
// routing header still fits within the ICMP payload limit. These are exactly
// what route() extracts from an inbound packet and what the relay queues.
func encodeChunks(t *testing.T, name, text, room string, key []byte) [][]byte {
	t.Helper()
	chunks, cnt, err := icmpchat.ChunkText(name, text, key, icmpchat.RelayHeaderLen(room))
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	msgID := icmpchat.RandMsgID()
	var out [][]byte
	for i, c := range chunks {
		m := &icmpchat.Message{
			Name:     name,
			Text:     string(c),
			MsgID:    msgID,
			ChunkIdx: uint8(i),
			ChunkCnt: cnt,
		}
		cp, err := icmpchat.Encode(m, key)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		out = append(out, cp)
	}
	return out
}

// relayWrap returns the full on-wire packets a relay client transmits: each
// chat payload from encodeChunks fronted with the visible relay routing header,
// exactly as sendLine builds them.
func relayWrap(t *testing.T, name, text, room string, key []byte) [][]byte {
	t.Helper()
	header, err := icmpchat.BuildRelayHeader(room)
	if err != nil {
		t.Fatalf("BuildRelayHeader: %v", err)
	}
	var pkts [][]byte
	for _, cp := range encodeChunks(t, name, text, room, key) {
		pkt := make([]byte, 0, len(header)+len(cp))
		pkt = append(pkt, header...)
		pkt = append(pkt, cp...)
		pkts = append(pkts, pkt)
	}
	return pkts
}

// relayE2ECases are the message shapes exercised end to end: a short cleartext
// message, a multi-chunk message, and an encrypted message.
var relayE2ECases = []struct {
	name string
	text string
	key  []byte
}{
	{"cleartext", "hello over the relay", nil},
	{"chunked", strings.Repeat("y", 2500), nil},
	{"encrypted", "a secret carried through the relay", icmpchat.NewKey("relay-e2e-key")},
}

// receiveRelayed reads from the client listener until a full message is
// reassembled or the deadline passes, returning the sender name and text.
func receiveRelayed(t *testing.T, l *icmpchat.Listener, deadline time.Time) (string, string, bool) {
	t.Helper()
	for time.Now().Before(deadline) {
		name, text, complete, err := l.ReadNext()
		if err != nil {
			t.Fatalf("client ReadNext: %v", err)
		}
		if complete {
			return name, text, true
		}
	}
	return "", "", false
}

// TestRelayDeliveryOverSockets confirms the relay's delivery leg over real ICMP
// sockets: a queued message is drained on a poll, re-wrapped with the deliver
// header, and sent as an ICMP echo reply (type 0) via SendReply; the client's
// Listener receives that reply, strips the header, decrypts, and reassembles the
// message. This is the pull-based path that makes relay chat work on macOS, and
// nothing else exercises it over a socket.
//
// Echo replies reach raw sockets on both macOS and Linux, so this runs on
// either with root. It skips when raw ICMP sockets are unavailable. Run with
// `sudo go test ./cmd/relay -run TestRelayDeliveryOverSockets -v`.
func TestRelayDeliveryOverSockets(t *testing.T) {
	relayL, err := icmpchat.NewListener("", "", nil)
	if err != nil {
		t.Skipf("relay raw ICMP socket unavailable (need root): %v", err)
	}
	defer relayL.Close()

	for _, tc := range relayE2ECases {
		t.Run(tc.name, func(t *testing.T) {
			const room = "e2e"
			bListener, err := icmpchat.NewListener("", relayE2EIP, tc.key)
			if err != nil {
				t.Skipf("client raw ICMP socket unavailable: %v", err)
			}
			defer bListener.Close()

			r := &rooms{
				members: map[string]map[string]time.Time{},
				queues:  map[string]map[string][][]byte{},
			}
			// Queue the message's chat payloads as route() would, then deliver
			// them on a poll. Inbound parsing (route/IsForwardableMessage) is
			// covered by the routing unit tests; here the focus is the socket
			// delivery, so the poll's id/seq are representative constants.
			for _, cp := range encodeChunks(t, "alice", tc.text, room, tc.key) {
				r.queue(room, relayE2EIP, cp)
			}
			r.deliverPoll(relayL, relayE2EIP, room, 0x4242, 7, false)

			name, text, ok := receiveRelayed(t, bListener, time.Now().Add(5*time.Second))
			if !ok {
				t.Fatalf("client never received the relayed message")
			}
			if name != "alice" {
				t.Fatalf("relayed sender = %q, want %q", name, "alice")
			}
			if text != tc.text {
				t.Fatalf("relayed text mismatch: got %d bytes, want %d bytes", len(text), len(tc.text))
			}
		})
	}
}

// TestRelayFullRoundTripOverSockets exercises both legs over real sockets: a
// client transmits a relay-wrapped message, the relay reads it with
// ReadEchoRequest and route, queues it, the client polls, and the relay drains
// and delivers it as an echo reply that the client receives and reassembles.
//
// The inbound leg needs the relay to receive the client's echo *requests* on a
// raw socket. Linux delivers those to raw sockets; the macOS kernel answers
// echo requests itself and never passes them to raw sockets (the same reason
// relay mode delivers via echo replies), so this full round trip is Linux-only.
// It skips elsewhere and when raw ICMP sockets are unavailable.
func TestRelayFullRoundTripOverSockets(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("relay receives echo requests on a raw socket only on Linux; macOS blocks them at the kernel")
	}
	relayL, err := icmpchat.NewListener("", "", nil)
	if err != nil {
		t.Skipf("relay raw ICMP socket unavailable (need root): %v", err)
	}
	defer relayL.Close()

	for _, tc := range relayE2ECases {
		t.Run(tc.name, func(t *testing.T) {
			const room = "e2e"
			bListener, err := icmpchat.NewListener("", relayE2EIP, tc.key)
			if err != nil {
				t.Skipf("client raw ICMP socket unavailable: %v", err)
			}
			defer bListener.Close()

			aSender, err := icmpchat.NewSender(relayE2EIP) // A -> relay (messages)
			if err != nil {
				t.Skipf("sender socket unavailable: %v", err)
			}
			defer aSender.Close()
			bSender, err := icmpchat.NewSender(relayE2EIP) // B -> relay (polls)
			if err != nil {
				t.Skipf("sender socket unavailable: %v", err)
			}
			defer bSender.Close()

			r := &rooms{
				members: map[string]map[string]time.Time{},
				queues:  map[string]map[string][][]byte{},
			}
			deadline := time.Now().Add(8 * time.Second)

			// 1. A transmits its (possibly chunked) message to the relay.
			pkts := relayWrap(t, "alice", tc.text, room, tc.key)
			for _, pkt := range pkts {
				if !aSender.Send(pkt) {
					t.Skip("loopback ICMP delivery unavailable in this environment")
				}
			}

			// 2. The relay reads each message off its socket (ReadEchoRequest)
			// and route() classifies it as forwardable, then queues it.
			queued := 0
			for queued < len(pkts) && time.Now().Before(deadline) {
				src, payload, _, _, ok, err := relayL.ReadEchoRequest()
				if err != nil {
					t.Fatalf("relay ReadEchoRequest: %v", err)
				}
				if !ok {
					continue
				}
				res := r.route(src.String(), payload)
				if res.room == "" || res.isPoll {
					continue
				}
				r.queue(res.room, relayE2EIP, res.chatPayload)
				queued++
			}
			if queued != len(pkts) {
				t.Fatalf("relay queued %d of %d message chunk(s) before deadline", queued, len(pkts))
			}

			// 3. B polls; the relay reads the poll and delivers the queue.
			poll, err := icmpchat.BuildPollHeader(room)
			if err != nil {
				t.Fatalf("BuildPollHeader: %v", err)
			}
			if !bSender.SendPoll(poll) {
				t.Skip("loopback ICMP delivery unavailable in this environment")
			}
			delivered := false
			for !delivered && time.Now().Before(deadline) {
				src, payload, id, seq, ok, err := relayL.ReadEchoRequest()
				if err != nil {
					t.Fatalf("relay ReadEchoRequest (poll): %v", err)
				}
				if !ok {
					continue
				}
				res := r.route(src.String(), payload)
				if !res.isPoll {
					continue
				}
				r.deliverPoll(relayL, src.String(), res.room, id, seq, false)
				delivered = true
			}
			if !delivered {
				t.Fatalf("relay never observed the poll")
			}

			// 4. B receives, decrypts, and reassembles the delivered message.
			name, text, ok := receiveRelayed(t, bListener, deadline)
			if !ok {
				t.Fatalf("client never received the relayed message")
			}
			if name != "alice" || text != tc.text {
				t.Fatalf("round-trip mismatch: name=%q textlen=%d want name=alice textlen=%d", name, len(text), len(tc.text))
			}
		})
	}
}
