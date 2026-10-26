package main

import (
	"bytes"
	"errors"
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

// Sender sends ICMP echo requests over an unprivileged UDP-wrapped ICMP
// socket. The kernel rewrites the ICMP identifier, so routing uses the payload,
// never the ID.
type Sender struct {
	conn *icmp.PacketConn
	peer *net.UDPAddr
}

// NewSender opens a UDP-ICMP socket bound to all interfaces. A raw-socket
// fallback is intentionally omitted: udp4 ICMP send is available unprivileged
// on macOS and Linux (verified), and raw send additionally needs root, so the
// fallback would be unreachable. Adding it would require a divergent Send path
// (raw reads include the IP header), so we keep the single verified path.
func NewSender(peerIP string) (*Sender, error) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return &Sender{
		conn: conn,
		peer: &net.UDPAddr{IP: net.ParseIP(peerIP), Port: 0},
	}, nil
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
		if _, err := s.conn.WriteTo(b, s.peer); err != nil {
			return false
		}
		if s.waitReply(payload) {
			return true
		}
	}
	return false
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
		rm, err := icmp.ParseMessage(1, buf[:n]) // ICMP is IP protocol 1
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

// Listener receives ICMP echo requests on a raw socket (needs root).
type Listener struct {
	conn  *icmp.PacketConn
	peer  string
	key   []byte
	reasm *reassembler
}

// NewListener opens a raw IPv4 ICMP socket bound to all interfaces. It fails
// without root privileges.
func NewListener(peer string, key []byte) (*Listener, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return &Listener{conn: conn, peer: peer, key: key, reasm: newReassembler()}, nil
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
	if !ok || ipAddr.IP.String() != l.peer {
		return "", "", false, nil
	}
	name, text, complete, dropped, perr := l.handlePacket(ipAddr.IP, buf[:n])
	if dropped || perr != nil {
		// Drop ignored, undecodable, or errored packets silently.
		return "", "", false, nil
	}
	return name, text, complete, nil
}

// handlePacket processes one raw IPv4/ICMP packet. It returns (name, text,
// complete, dropped, err): complete is true only when a full message arrived;
// dropped is true for ignored/undecodable packets; err is non-nil only for
// structural failures like a malformed IP header.
func (l *Listener) handlePacket(src net.IP, pkt []byte) (name, text string, complete, dropped bool, err error) {
	if src.String() != l.peer {
		return "", "", false, true, nil
	}
	raw, err := stripIPHeader(pkt)
	if err != nil {
		return "", "", false, true, err
	}
	rm, err := icmp.ParseMessage(1, raw)
	if err != nil {
		return "", "", false, true, err
	}
	// Only echo requests (type 8) carry our messages; ignore echo replies and
	// everything else.
	if rm.Type != ipv4.ICMPTypeEcho {
		return "", "", false, true, nil
	}
	e, ok := rm.Body.(*icmp.Echo)
	if !ok {
		return "", "", false, true, nil
	}
	msg, err := decode(e.Data, l.key)
	if err != nil {
		return "", "", false, true, nil
	}
	text, complete = l.reasm.Add(msg)
	return msg.Name, text, complete, false, nil
}

// stripIPHeader removes the leading IPv4 header; its length (IHL, in 32-bit
// words) is in the first byte. macOS and Linux both deliver the header first.
func stripIPHeader(b []byte) ([]byte, error) {
	if len(b) < 20 {
		return nil, errShortPacket
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return nil, errShortPacket
	}
	return b[ihl:], nil
}
