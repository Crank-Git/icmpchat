// Command relay runs an ICMP chat relay: a one-to-many server that forwards
// messages between clients sharing a chat room. Clients that cannot reach each
// other directly (firewalls, NAT, or simply to chat in a group) send to the
// relay with --relay; the relay delivers each message to every other member of
// the room.
//
// The relay needs a raw ICMP socket, so run it with sudo:
//
//	sudo relay --addr 192.168.1.10
//
// Clients then run:
//
//	icmpchat --relay 192.168.1.10 --name alice
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"icmpchat/internal/icmpchat"
)

func main() {
	addr := flag.String("addr", "", "relay LAN IP clients should pass to --relay (best-effort detected if empty)")
	ttl := flag.Duration("ttl", 60*time.Second, "drop members inactive for longer than this")
	pruneEvery := flag.Duration("prune-every", 30*time.Second, "how often to drop inactive members")
	verbose := flag.Bool("verbose", false, "log forwarded messages and poll drains to stderr")
	flag.Parse()

	l, err := icmpchat.NewListener("", "", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay needs root: run with sudo (could not open raw ICMP socket: %v)\n", err)
		os.Exit(1)
	}
	defer l.Close()

	myAddr := *addr
	if myAddr == "" {
		myAddr = detectLANIP()
	}
	if myAddr == "" {
		fmt.Fprintln(os.Stderr, "relay: could not detect a LAN IP; pass --addr <your-lan-ip> so clients know where to send")
	} else {
		fmt.Printf("icmpchat relay listening on %s\n", myAddr)
		fmt.Printf("clients: icmpchat --relay %s --name <nick>\n", myAddr)
	}

	r := &rooms{members: map[string]map[string]time.Time{}, queues: map[string]map[string][][]byte{}}
	go r.pruneLoop(*ttl, *pruneEvery)

	for {
		src, payload, id, seq, ok, err := l.ReadEchoRequest()
		if err != nil || !ok {
			continue
		}
		res := r.route(src.String(), payload)
		if res.room == "" {
			continue
		}
		if res.isPoll {
			// A poll joins/refreshes the room and asks for anything queued.
			r.deliverPoll(l, src.String(), res.room, id, seq, *verbose)
			continue
		}
		// A message queues for every other member; delivery happens on their
		// next poll, which is how clients that cannot receive echo requests
		// (such as macOS) learn of it.
		for _, tgt := range res.targets {
			r.queue(res.room, tgt, res.chatPayload)
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "relay: room %q queued for %d member(s)\n", res.room, len(res.targets))
		}
	}
}

// maxQueue caps how many messages are held for a member; the oldest is dropped
// when a member is more chatty than quiet.
const maxQueue = 64

// rooms tracks which client IPs belong to each chat room, their last-seen time,
// and any chat payloads queued for them awaiting the next poll.
type rooms struct {
	mu      sync.Mutex
	members map[string]map[string]time.Time // room -> ip -> lastSeen
	queues  map[string]map[string][][]byte  // room -> ip -> queued chat payloads
}

func (r *rooms) add(room, ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.members[room] == nil {
		r.members[room] = map[string]time.Time{}
	}
	r.members[room][ip] = time.Now()
}

// memberIPs returns the member IPs of room, excluding except.
func (r *rooms) memberIPs(room, except string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for ip := range r.members[room] {
		if ip != except {
			out = append(out, ip)
		}
	}
	return out
}

func (r *rooms) prune(deadline time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for room, members := range r.members {
		for ip, last := range members {
			if last.Before(deadline) {
				delete(members, ip)
				delete(r.queues[room], ip)
			}
		}
		if len(members) == 0 {
			delete(r.members, room)
			delete(r.queues, room)
		}
	}
}

// queue appends chatPayload to ip's queue for room, dropping the oldest when the
// queue is full.
func (r *rooms) queue(room, ip string, chatPayload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.queues[room] == nil {
		r.queues[room] = map[string][][]byte{}
	}
	q := r.queues[room][ip]
	q = append(q, chatPayload)
	if len(q) > maxQueue {
		q = q[len(q)-maxQueue:]
	}
	r.queues[room][ip] = q
}

// drain returns and clears ip's queue for room, oldest first, so each queued
// message is delivered exactly once.
func (r *rooms) drain(room, ip string) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	roomQ := r.queues[room]
	if roomQ == nil {
		return nil
	}
	q := roomQ[ip]
	roomQ[ip] = nil
	if len(q) == 0 {
		return nil
	}
	return q
}

// deliverPoll drains a poller's queued messages and sends each as an echo reply
// (type 0) carrying the relayFlag|deliverFlag header, copying the poll's ICMP id
// and seq. It is how the relay delivers queued messages to clients, including
// those that cannot receive echo requests (such as macOS).
func (r *rooms) deliverPoll(l *icmpchat.Listener, src, room string, id, seq int, verbose bool) {
	msgs := r.drain(room, src)
	for _, cp := range msgs {
		header, err := icmpchat.BuildDeliverHeader(room)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "relay: build deliver header for %s: %v\n", src, err)
			}
			continue
		}
		out := make([]byte, 0, len(header)+len(cp))
		out = append(out, header...)
		out = append(out, cp...)
		if !l.SendReply(src, id, seq, out) {
			if verbose {
				fmt.Fprintf(os.Stderr, "relay: deliver to %s failed\n", src)
			}
		}
	}
	if verbose && len(msgs) > 0 {
		fmt.Fprintf(os.Stderr, "relay: delivered %d to %s (room %q)\n", len(msgs), src, room)
	}
}

func (r *rooms) pruneLoop(ttl, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for range ticker.C {
		r.prune(time.Now().Add(-ttl))
	}
}

// routeResult describes how the caller should handle a parsed relay packet.
type routeResult struct {
	room        string
	isPoll      bool
	chatPayload []byte
	targets     []string
}

// route parses a relay packet, records src as a member of the room, and reports
// whether it is a poll (which the caller drains) or a message (which the caller
// queues to the other targets). A delivery echo-back -- the kernel auto-acking
// the relay's echo replies -- is rejected, so it is never re-forwarded. It
// performs no network I/O so the routing decision can be unit tested.
func (r *rooms) route(src string, payload []byte) routeResult {
	// A poll is exactly the relay header with the poll bit and nothing after it.
	if room, ok := icmpchat.ParsePoll(payload); ok {
		r.add(room, src)
		return routeResult{room: room, isPoll: true}
	}
	if room, chatPayload, ok := icmpchat.IsForwardableMessage(payload); ok {
		// A forwardable message carries the relay flag only. A delivery
		// echo-back (the kernel auto-acking our echo replies) carries the
		// deliver bit and is rejected by IsForwardableMessage, so it is never
		// re-forwarded to other members.
		r.add(room, src)
		return routeResult{room: room, chatPayload: chatPayload, targets: r.memberIPs(room, src)}
	}
	return routeResult{}
}

// detectLANIP returns the first non-loopback IPv4 address on the host. It is a
// best-effort default; --addr should be set for reliability.
func detectLANIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}
