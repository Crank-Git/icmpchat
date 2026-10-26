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
	verbose := flag.Bool("verbose", false, "log each forwarded message to stderr")
	flag.Parse()

	l, err := icmpchat.NewListener("", "", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay needs root: run with sudo (could not open raw ICMP socket: %v)\n", err)
		os.Exit(1)
	}
	defer l.Close()

	sender, err := icmpchat.NewSender("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay cannot open sender socket: %v\n", err)
		os.Exit(1)
	}
	defer sender.Close()

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

	r := &rooms{members: map[string]map[string]time.Time{}}
	go r.pruneLoop(*ttl, *pruneEvery)

	for {
		src, payload, ok, err := l.ReadEchoRequest()
		if err != nil {
			continue
		}
		if !ok {
			continue
		}
		room, chatPayload, targets, ok := r.route(src.String(), payload)
		if !ok {
			continue
		}
		r.sendAll(sender, room, chatPayload, targets, *verbose)
	}
}

// rooms tracks which client IPs belong to each chat room and prunes stale ones.
type rooms struct {
	mu      sync.Mutex
	members map[string]map[string]time.Time // room -> ip -> lastSeen
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
			}
		}
		if len(members) == 0 {
			delete(r.members, room)
		}
	}
}

func (r *rooms) pruneLoop(ttl, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for range ticker.C {
		r.prune(time.Now().Add(-ttl))
	}
}

// route parses a relay payload, records src as a member of the room, and
// returns the room, the chat payload to forward, and the other members to
// deliver it to. ok is false for non-relay or malformed payloads. It performs no
// network I/O so the routing decision can be unit tested.
func (r *rooms) route(src string, payload []byte) (room string, chatPayload []byte, targets []string, ok bool) {
	room, ok, err := icmpchat.RelayRoom(payload)
	if err != nil || !ok {
		return "", nil, nil, false
	}
	chatPayload = payload[icmpchat.RelayHeaderLen(room):]
	if len(chatPayload) < 4 || string(chatPayload[0:4]) != "ICHT" {
		return "", nil, nil, false
	}
	r.add(room, src)
	return room, chatPayload, r.memberIPs(room, src), true
}

// sendAll re-wraps the chat payload in a fresh relay header for room and sends
// it to every target. It is fire-and-forget: delivery acks come from each
// member's kernel auto-reply, not from the relay.
func (r *rooms) sendAll(s *icmpchat.Sender, room string, chatPayload []byte, targets []string, verbose bool) {
	header, err := icmpchat.BuildRelayHeader(room)
	if err != nil {
		return
	}
	out := make([]byte, 0, len(header)+len(chatPayload))
	out = append(out, header...)
	out = append(out, chatPayload...)
	for _, m := range targets {
		if s.SendRaw(m, out) {
			continue
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "relay: forward to %s failed\n", m)
		}
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "relay: room %q forwarded to %d member(s)\n", room, len(targets))
	}
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
