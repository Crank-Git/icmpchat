package icmpchat

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Wire format (ICMP Echo payload, big-endian):
//
//	magic[4]="ICHT" ver[1] flags[1] msgid[4] chunkIdx[1] chunkCnt[1] nameLen[1] name text
//
// With a key, bytes after the 5-byte header (magic+ver) are AEAD-sealed and a
// 12-byte nonce is prepended; the visible header lets the listener filter
// without a key.

const (
	magicStr      = "ICHT"
	protoVer      = 1
	maxPayload    = 1000
	nonceLen      = 12
	aeadOverhead  = 16 // GCM authentication tag
	headerLen     = 5  // magic(4) + ver(1)
	fullHeaderLen = 13 // magic+ver+flags+msgid+chunkIdx+chunkCnt+nameLen

	relayFlag   = 0x01 // flags bit: payload carries a visible relay routing header
	pollFlag    = 0x02 // flags bit: echo request is a poll (client -> relay), payload is exactly the relay header
	deliverFlag = 0x04 // flags bit: echo reply carries a queued chat payload (relay -> client)
)

// relayHeaderBase is the length of the visible relay header for an empty room:
// magic(4) + ver(1) + flags(1) + roomLen(1) + room(0).
const relayHeaderBase = 7

var (
	magic          = []byte(magicStr)
	errBadMagic    = errors.New("icmpchat: bad magic")
	errBadVer      = errors.New("icmpchat: unsupported protocol version")
	errShort       = errors.New("icmpchat: packet too short")
	errNameTooLong = errors.New("icmpchat: name too long (max 255 bytes)")
	errRoomTooLong = errors.New("icmpchat: room too long (max 255 bytes)")
	errNotRelay    = errors.New("icmpchat: not a relay payload")
)

// relayHeaderLen returns the on-wire length of the visible relay routing
// header for the given room name.
func RelayHeaderLen(room string) int {
	return relayHeaderBase + len(room)
}

// BuildRelayHeader returns the visible routing prefix for a relay message. The
// relay flag marks the payload so receivers know to strip it before decoding;
// the room lets the relay route to the right chat room. This header sits in
// front of the (possibly encrypted) chat payload and is never sealed, so a
// relay can route without the key.
func BuildRelayHeader(room string) ([]byte, error) {
	return buildRelayHeaderFlags(room, relayFlag)
}

// BuildPollHeader builds the visible relay header for a client->relay poll. The
// relayFlag|pollFlag bits mark it so the relay recognizes it as a poll rather
// than a chat message; the payload is exactly this header and nothing else.
func BuildPollHeader(room string) ([]byte, error) {
	return buildRelayHeaderFlags(room, relayFlag|pollFlag)
}

// BuildDeliverHeader builds the visible relay header for a relay->client
// delivery. The relayFlag|deliverFlag bits mark it so the client accepts it as a
// queued message and not as the kernel's echo-back of its own poll or message.
func BuildDeliverHeader(room string) ([]byte, error) {
	return buildRelayHeaderFlags(room, relayFlag|deliverFlag)
}

// buildRelayHeaderFlags builds the visible relay header with the given flags.
func buildRelayHeaderFlags(room string, flags byte) ([]byte, error) {
	if len(room) > 255 {
		return nil, errRoomTooLong
	}
	b := make([]byte, RelayHeaderLen(room))
	copy(b[0:4], magic)
	b[4] = protoVer
	b[5] = flags
	b[6] = uint8(len(room))
	copy(b[7:], room)
	return b, nil
}

// relayRoom inspects a payload's leading bytes and reports whether they form a
// relay header, returning the room when they do. A clear relay flag means the
// payload is a plain chat message and relayRoom reports ok=false.
func RelayRoom(payload []byte) (room string, ok bool, err error) {
	if len(payload) < relayHeaderBase {
		return "", false, errShort
	}
	if !bytes.Equal(payload[0:4], magic) || payload[4] != protoVer {
		return "", false, errBadMagic
	}
	if payload[5]&(relayFlag|pollFlag|deliverFlag) == 0 {
		return "", false, errNotRelay
	}
	roomLen := int(payload[6])
	if len(payload) < relayHeaderBase+roomLen {
		return "", false, errShort
	}
	// The relay header fronts a chat payload that must itself begin with the
	// ICHT magic. That requirement is what separates a genuine relay header from
	// the start of an encrypted (non-relay) message: after magic+ver an encrypted
	// payload carries a random nonce, whose first byte can coincidentally set the
	// relay-flag bit and whose next byte can coincidentally read as a room length.
	// Requiring the inner payload to start with ICHT rejects those false positives.
	if inner := payload[relayHeaderBase+roomLen:]; len(inner) < 4 || !bytes.Equal(inner[0:4], magic) {
		return "", false, errNotRelay
	}
	return string(payload[7 : 7+roomLen]), true, nil
}

// splitRelay separates a visible relay header from the chat payload it fronts.
// It returns the chat payload and true when a relay header was present, or the
// original buffer and false for a plain chat message.
func splitRelay(payload []byte) ([]byte, bool) {
	room, ok, err := RelayRoom(payload)
	if err != nil || !ok {
		return payload, false
	}
	if len(payload) < RelayHeaderLen(room) {
		return payload, false
	}
	return payload[RelayHeaderLen(room):], true
}

// IsForwardableMessage reports whether payload is a relay-wrapped chat message
// the relay should forward: a relay header carrying the relay flag only (not a
// poll, not a delivery) followed by an inner ICHT message. A delivery
// echo-back -- the kernel auto-acking the relay's echo replies (type 0) --
// carries the deliver bit and is rejected here, so the relay never re-forwards
// its own output.
func IsForwardableMessage(payload []byte) (room string, chatPayload []byte, ok bool) {
	if len(payload) < relayHeaderBase {
		return "", nil, false
	}
	if !bytes.Equal(payload[0:4], magic) || payload[4] != protoVer || payload[5] != relayFlag {
		// relayFlag only distinguishes a forwardable message from a poll or a
		// delivery echo-back; anything else is not forwarded.
		return "", nil, false
	}
	roomLen := int(payload[6])
	if len(payload) < relayHeaderBase+roomLen {
		return "", nil, false
	}
	room = string(payload[7 : 7+roomLen])
	chatPayload = payload[relayHeaderBase+roomLen:]
	if len(chatPayload) < 4 || !bytes.Equal(chatPayload[0:4], magic) {
		return "", nil, false
	}
	return room, chatPayload, true
}

// ParsePoll reports whether payload is a poll: a relay header (relayFlag|pollFlag)
// with no trailing bytes. It returns the room. ok is false for anything else,
// including relay headers that carry a chat payload (those are messages, not
// polls) and headers that are missing the poll bit.
func ParsePoll(payload []byte) (room string, ok bool) {
	if len(payload) < relayHeaderBase {
		return "", false
	}
	if !bytes.Equal(payload[0:4], magic) || payload[4] != protoVer {
		return "", false
	}
	if payload[5]&(relayFlag|pollFlag) != (relayFlag | pollFlag) {
		return "", false
	}
	roomLen := int(payload[6])
	// A poll is exactly the relay header and nothing after it; trailing bytes
	// mean this is a message, not a poll.
	if len(payload) != relayHeaderBase+roomLen {
		return "", false
	}
	return string(payload[7 : 7+roomLen]), true
}

// ParseDeliver reports whether payload is a relay delivery: a relay header with
// relayFlag|deliverFlag followed by the inner ICHT chat payload. It returns the
// chat payload. ok is false for polls, plain messages, encrypted nonces, and
// malformed packets, so a delivery is never mistaken for anything else.
func ParseDeliver(payload []byte) (chatPayload []byte, ok bool) {
	if len(payload) < relayHeaderBase {
		return nil, false
	}
	if !bytes.Equal(payload[0:4], magic) || payload[4] != protoVer {
		return nil, false
	}
	if payload[5]&(relayFlag|deliverFlag) != (relayFlag | deliverFlag) {
		return nil, false
	}
	roomLen := int(payload[6])
	if len(payload) < relayHeaderBase+roomLen {
		return nil, false
	}
	inner := payload[relayHeaderBase+roomLen:]
	// Require the inner payload to start with the ICHT magic, the same guard as
	// RelayRoom, so an encrypted nonce can't be mistaken for a delivery.
	if len(inner) < 4 || !bytes.Equal(inner[0:4], magic) {
		return nil, false
	}
	return inner, true
}

// Message is one chunk of a chat message.
type Message struct {
	Name     string
	Text     string
	MsgID    uint32
	Flags    uint8
	ChunkIdx uint8
	ChunkCnt uint8
}

// RandMsgID returns a random message id used to identify a chunked message's
// fragments during reassembly.
func RandMsgID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

// NewKey derives a 32-byte key from a passphrase via SHA-256.
func NewKey(passphrase string) []byte {
	sum := sha256.Sum256([]byte(passphrase))
	return sum[:]
}

func newAEAD(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("icmpchat: invalid AEAD key length: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("icmpchat: failed to create GCM: " + err.Error())
	}
	return aead
}

// Encode serializes a message into an on-wire ICMP payload. With a key the
// payload after the 5-byte header is sealed with AES-256-GCM and a random
// nonce is prepended; the visible header stays unencrypted so listeners and
// relays can route without the key.
func Encode(m *Message, key []byte) ([]byte, error) {
	if len(m.Name) > 255 {
		return nil, errNameTooLong
	}
	buf := make([]byte, fullHeaderLen+len(m.Name)+len(m.Text))
	copy(buf[0:4], magic)
	buf[4] = protoVer
	buf[5] = m.Flags
	binary.BigEndian.PutUint32(buf[6:10], m.MsgID)
	buf[10] = m.ChunkIdx
	buf[11] = m.ChunkCnt
	buf[12] = uint8(len(m.Name))
	copy(buf[fullHeaderLen:], m.Name)
	copy(buf[fullHeaderLen+len(m.Name):], m.Text)

	if key == nil {
		return buf, nil
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := newAEAD(key).Seal(nil, nonce, buf[headerLen:], nil)
	out := make([]byte, 0, nonceLen+len(sealed))
	out = append(out, buf[:headerLen]...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// decode parses an ICMP payload into a Message, dropping packets silently on
// any error (bad magic, truncation, auth failure).
func decode(payload []byte, key []byte) (*Message, error) {
	if len(payload) < headerLen {
		return nil, errShort
	}
	if !bytes.Equal(payload[0:4], magic) {
		return nil, errBadMagic
	}
	if payload[4] != protoVer {
		return nil, errBadVer
	}

	var plaintext []byte
	if key != nil {
		if len(payload) < headerLen+nonceLen+aeadOverhead {
			return nil, errShort
		}
		nonce := payload[headerLen : headerLen+nonceLen]
		ciphertext := payload[headerLen+nonceLen:]
		var err error
		plaintext, err = newAEAD(key).Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
	} else {
		plaintext = payload[headerLen:]
	}

	if len(plaintext) < 8 { // flags+msgid+chunkIdx+chunkCnt+nameLen
		return nil, errShort
	}
	m := &Message{}
	m.Flags = plaintext[0]
	m.MsgID = binary.BigEndian.Uint32(plaintext[1:5])
	m.ChunkIdx = plaintext[5]
	m.ChunkCnt = plaintext[6]
	nameLen := int(plaintext[7])
	if len(plaintext) < 8+nameLen {
		return nil, errShort
	}
	m.Name = string(plaintext[8 : 8+nameLen])
	m.Text = string(plaintext[8+nameLen:])
	if m.ChunkIdx >= m.ChunkCnt {
		return nil, errShort
	}
	return m, nil
}

// chunkText splits text into chunks that each fit within maxPayload bytes once
// encoded. The name is carried in every chunk, so it is subtracted from the
// per-chunk budget.
// ChunkText splits text into chunks that each fit within maxPayload bytes once
// encoded, accounting for framing overhead added on top of each chunk (such as
// a relay routing header). The name is carried in every chunk, so it is
// subtracted from the per-chunk budget.
func ChunkText(name, text string, key []byte, overhead int) ([][]byte, uint8, error) {
	extra := 0
	if key != nil {
		extra = nonceLen + aeadOverhead
	}
	// Account for any framing (such as a relay routing header) added on top of
	// each chunk so the total ICMP payload never exceeds maxPayload.
	capacity := maxPayload - fullHeaderLen - len(name) - extra - overhead
	if capacity < 1 {
		capacity = 1
	}
	var chunks [][]byte
	for i := 0; i < len(text); i += capacity {
		end := i + capacity
		if end > len(text) {
			end = len(text)
		}
		chunks = append(chunks, []byte(text[i:end]))
	}
	if len(chunks) == 0 {
		chunks = [][]byte{{}}
	}
	if len(chunks) > 255 {
		return nil, 0, fmt.Errorf("icmpchat: message too large to chunk (%d chunks)", len(chunks))
	}
	return chunks, uint8(len(chunks)), nil
}

// reassembler collects message chunks keyed by MsgID.
type reassembler struct {
	frags map[uint32]*fragment
}

type fragment struct {
	chunkCnt uint8
	name     string
	chunks   map[uint8]string
}

func newReassembler() *reassembler {
	return &reassembler{frags: map[uint32]*fragment{}}
}

// Add records one chunk and returns (text, complete); complete is true only
// when the final chunk of a message has arrived.
func (rs *reassembler) Add(m *Message) (string, bool) {
	if m.ChunkCnt == 0 {
		return "", false
	}
	f := rs.frags[m.MsgID]
	if f == nil {
		f = &fragment{chunkCnt: m.ChunkCnt, name: m.Name, chunks: map[uint8]string{}}
		rs.frags[m.MsgID] = f
	}
	if f.chunkCnt != m.ChunkCnt {
		// A different stream reused this MsgID; drop the mismatch.
		return "", false
	}
	f.name = m.Name
	f.chunks[m.ChunkIdx] = m.Text
	if len(f.chunks) != int(f.chunkCnt) {
		return "", false
	}
	var sb strings.Builder
	for i := 0; i < int(f.chunkCnt); i++ {
		sb.WriteString(f.chunks[uint8(i)])
	}
	delete(rs.frags, m.MsgID)
	return sb.String(), true
}
