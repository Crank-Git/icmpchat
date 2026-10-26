package icmpchat

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var seqCounter uint32

func nextSeq() int {
	return int(atomic.AddUint32(&seqCounter, 1))
}

const (
	replyTimeout      = 2 * time.Second // echo reply doubles as delivery ack
	listenReadTimeout = 500 * time.Millisecond
	readBufferSize    = 1500 // one IP packet (header + 1000-byte payload)
)

var (
	errShortPacket = errors.New("icmpchat: packet shorter than IP header")
)

// Sender sends ICMP echo requests and uses the kernel's echo reply as a
// delivery acknowledgment. Routing uses the payload, never the ICMP ID, which
// the kernel rewrites on UDP-wrapped sockets.
//
// The primary path is an unprivileged udp4 ICMP socket (works on macOS and
// most Linux hosts). Some hardened Linux hosts (e.g. containers that block
// SOCK_DGRAM ICMP) reject that even as root; there the sender falls back to a
// raw ip4:icmp socket, which requires root. Both paths marshal the same ICMP
// message; only the destination address type and the reply read differ.
type Sender struct {
	conn *icmp.PacketConn
	peer *net.UDPAddr // destination for the udp4 (unprivileged) path
	dst  *net.IPAddr  // destination for the raw fallback path
	raw  bool         // true when the raw-socket fallback is in use
}

// NewSender opens an ICMP echo-request socket bound to all interfaces. It
// first tries an unprivileged udp4 ICMP socket (works on macOS and most Linux
// hosts). When the OS blocks that -- common on hardened Linux hosts that deny
// SOCK_DGRAM ICMP even as root -- it falls back to a raw ip4:icmp socket,
// which requires root. The returned Sender drives both paths identically.
func NewSender(peerIP string) (*Sender, error) {
	ip := net.ParseIP(peerIP)
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err == nil {
		return &Sender{conn: conn, peer: &net.UDPAddr{IP: ip, Port: 0}}, nil
	}
	raw, rerr := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if rerr != nil {
		return nil, fmt.Errorf("icmpchat: sender socket: udp4 ICMP: %v; raw ICMP: %v", err, rerr)
	}
	return &Sender{conn: raw, dst: &net.IPAddr{IP: ip}, raw: true}, nil
}

func (s *Sender) Close() {
	_ = s.conn.Close()
}

// Send writes one echo request carrying payload and returns true when the
// matching echo reply arrives within replyTimeout, retrying once.
func (s *Sender) Send(payload []byte) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{Seq: nextSeq(), Data: payload},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	for attempt := 0; attempt < 2; attempt++ {
		var err error
		if s.raw {
			_, err = s.conn.WriteTo(b, s.dst)
		} else {
			_, err = s.conn.WriteTo(b, s.peer)
		}
		if err != nil {
			return false
		}
		if s.waitReply(payload) {
			return true
		}
	}
	return false
}

// SendRaw writes one echo request to ip without waiting for a reply. The relay
// uses it to forward messages to many members quickly; delivery acks come
// separately from each member's kernel auto-reply.
func (s *Sender) SendRaw(ip string, payload []byte) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{Seq: nextSeq(), Data: payload},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	ipn := net.ParseIP(ip)
	var addr net.Addr
	if s.raw {
		addr = &net.IPAddr{IP: ipn}
	} else {
		addr = &net.UDPAddr{IP: ipn}
	}
	_, err = s.conn.WriteTo(b, addr)
	return err == nil
}

// waitReply reads until the echo reply carrying payload arrives or the
// deadline passes, then clears the deadline so the socket can be reused.
func (s *Sender) waitReply(payload []byte) bool {
	_ = s.conn.SetReadDeadline(time.Now().Add(replyTimeout))
	defer s.conn.SetReadDeadline(time.Time{})
	buf := make([]byte, readBufferSize)
	for {
		n, _, err := s.conn.ReadFrom(buf)
		if err != nil {
			return false
		}
		// The udp4 path returns raw ICMP; the raw path returns the ICMP message
		// possibly preceded by an IPv4 header. stripIPHeader handles both.
		raw, err := stripIPHeader(buf[:n])
		if err != nil {
			continue
		}
		rm, err := icmp.ParseMessage(1, raw) // ICMP is IP protocol 1
		if err != nil {
			continue
		}
		e, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if bytes.Equal(e.Data, payload) {
			return true
		}
	}
}

// Listener receives ICMP echo requests on a raw socket (needs root). When
// relay is set, it also accepts messages forwarded by the relay at that IP.
type Listener struct {
	conn  *icmp.PacketConn
	peer  string // direct peer; packets from here are decoded as plain messages
	relay string // relay IP; packets from here carry a relay routing header
	key   []byte
	reasm *reassembler
}

// NewListener opens a raw IPv4 ICMP socket bound to all interfaces. It fails
// without root privileges. relay may be empty for direct (peer-only) use.
func NewListener(peer string, relay string, key []byte) (*Listener, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return &Listener{conn: conn, peer: peer, relay: relay, key: key, reasm: newReassembler()}, nil
}

func (l *Listener) Close() {
	_ = l.conn.Close()
}

// ReadNext reads one raw packet and returns (name, text, complete, err). It
// returns complete=true when a full message arrived; ignored or undecodable
// packets yield (,,false,nil) so the caller can loop.
func (l *Listener) ReadNext() (string, string, bool, error) {
	_ = l.conn.SetReadDeadline(time.Now().Add(listenReadTimeout))
	defer l.conn.SetReadDeadline(time.Time{})
	buf := make([]byte, readBufferSize)
	n, raddr, err := l.conn.ReadFrom(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	ipAddr, ok := raddr.(*net.IPAddr)
	if !ok {
		return "", "", false, nil
	}
	if ipAddr.IP.String() != l.peer && (l.relay == "" || ipAddr.IP.String() != l.relay) {
		return "", "", false, nil
	}
	name, text, complete, dropped, perr := l.handlePacket(ipAddr.IP, buf[:n])
	if dropped || perr != nil {
		// Drop ignored, undecodable, or errored packets silently.
		return "", "", false, nil
	}
	return name, text, complete, nil
}

// ReadEchoRequest reads one raw packet and returns the source IP and the echo
// request payload (ICMP data, IPv4 header stripped). Echo replies and non-echo
// or undecodable-header packets yield ok=false so the caller can loop.
func (l *Listener) ReadEchoRequest() (src net.IP, payload []byte, id, seq int, ok bool, err error) {
	_ = l.conn.SetReadDeadline(time.Now().Add(listenReadTimeout))
	defer l.conn.SetReadDeadline(time.Time{})
	buf := make([]byte, readBufferSize)
	n, raddr, err := l.conn.ReadFrom(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, nil, 0, 0, false, nil
		}
		return nil, nil, 0, 0, false, err
	}
	ipAddr, ok := raddr.(*net.IPAddr)
	if !ok {
		return nil, nil, 0, 0, false, nil
	}
	raw, err := stripIPHeader(buf[:n])
	if err != nil {
		return nil, nil, 0, 0, false, nil
	}
	// parseEchoRequest is the guard: it accepts echo requests (type 8) but
	// rejects echo replies (type 0) and anything else, so the relay never
	// re-forwards the kernel's auto-acks of its own polls and messages.
	payload, ok = parseEchoRequest(raw)
	if !ok {
		return nil, nil, 0, 0, false, nil
	}
	rm, err := icmp.ParseMessage(1, raw)
	if err != nil {
		return nil, nil, 0, 0, false, nil
	}
	e, ok := rm.Body.(*icmp.Echo)
	if !ok {
		return nil, nil, 0, 0, false, nil
	}
	return ipAddr.IP, payload, e.ID, e.Seq, true, nil
}

// SendReply writes one echo reply (type 0) to ip carrying payload. It uses the
// raw ip4:icmp socket, which is required because ping (udp4) sockets can only
// send echo requests; the relay delivers queued messages as echo replies so
// clients that cannot receive echo requests (such as macOS) can still get them
// on poll.
func (l *Listener) SendReply(ip string, id, seq int, payload []byte) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: payload},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	_, err = l.conn.WriteTo(b, &net.IPAddr{IP: net.ParseIP(ip)})
	return err == nil
}

// handlePacket processes one raw IPv4/ICMP packet. It returns (name, text,
// complete, dropped, err): complete is true only when a full message arrived;
// dropped is true for ignored/undecodable packets; err is non-nil only for
// structural failures like a malformed IP header.
func (l *Listener) handlePacket(src net.IP, pkt []byte) (name, text string, complete, dropped bool, err error) {
	// In direct mode accept only the peer; in relay mode accept only the relay.
	// l.peer is empty when relaying, so a bare `src != l.peer` would drop every
	// relay-forwarded message — mirror ReadNext's filter here.
	if src.String() != l.peer && (l.relay == "" || src.String() != l.relay) {
		return "", "", false, true, nil
	}
	raw, err := stripIPHeader(pkt)
	if err != nil {
		return "", "", false, true, err
	}
	rm, err := icmp.ParseMessage(1, raw)
	if err != nil {
		return "", "", false, true, nil
	}
	if l.relay != "" && l.peer == "" {
		// Relay mode: deliveries arrive as echo replies (type 0) from the relay.
		return l.handleRelayReply(rm)
	}
	// Direct mode: messages arrive as echo requests (type 8) from the peer.
	return l.handleDirectMessage(rm)
}

// handleDirectMessage decodes a direct-mode message: an echo request (type 8)
// from the peer.
func (l *Listener) handleDirectMessage(rm *icmp.Message) (string, string, bool, bool, error) {
	e, ok := rm.Body.(*icmp.Echo)
	if !ok || rm.Type != ipv4.ICMPTypeEcho {
		// Only echo requests carry direct messages; ignore replies and anything
		// else (in particular the kernel's echo-back of our own sends).
		return "", "", false, true, nil
	}
	msg, err := decode(e.Data, l.key)
	if err != nil {
		return "", "", false, true, nil
	}
	text, complete := l.reasm.Add(msg)
	return msg.Name, text, complete, false, nil
}

// handleRelayReply decodes a relay-mode delivery: an echo reply (type 0) from
// the relay carrying a queued chat payload. Everything else from the relay is
// ignored, including the kernel's echo-back of our own polls and messages, which
// are replies too but carry no deliverFlag.
func (l *Listener) handleRelayReply(rm *icmp.Message) (string, string, bool, bool, error) {
	e, ok := rm.Body.(*icmp.Echo)
	if !ok || rm.Type != ipv4.ICMPTypeEchoReply {
		return "", "", false, true, nil
	}
	chatPayload, ok := ParseDeliver(e.Data)
	if !ok {
		return "", "", false, true, nil
	}
	msg, err := decode(chatPayload, l.key)
	if err != nil {
		return "", "", false, true, nil
	}
	text, complete := l.reasm.Add(msg)
	return msg.Name, text, complete, false, nil
}

// parseEchoRequest validates a raw ICMP payload (IPv4 header already stripped)
// and returns the echo request data. ok is false for echo replies (type 0) and
// any non-echo or malformed message, so callers can loop past them. This is the
// shared guard that keeps the relay from re-forwarding its own auto-acks.
func parseEchoRequest(raw []byte) (payload []byte, ok bool) {
	rm, err := icmp.ParseMessage(1, raw)
	if err != nil {
		return nil, false
	}
	if rm.Type != ipv4.ICMPTypeEcho {
		return nil, false
	}
	e, ok := rm.Body.(*icmp.Echo)
	if !ok {
		return nil, false
	}
	return e.Data, true
}

// stripIPHeader removes the leading IPv4 header when present. The header's
// length (IHL, in 32-bit words) is in the first byte. Most kernels deliver the
// ICMP message preceded by the IPv4 header (first byte 0x45), but some hosts
// deliver the raw ICMP message without it (first byte is the ICMP type, e.g.
// 0x00). The version nibble distinguishes the two: only strip when it is 4.
func stripIPHeader(b []byte) ([]byte, error) {
	if len(b) < 20 {
		return nil, errShortPacket
	}
	if b[0]>>4 != 4 {
		return b, nil // no IPv4 header present
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return nil, errShortPacket
	}
	return b[ihl:], nil
}
