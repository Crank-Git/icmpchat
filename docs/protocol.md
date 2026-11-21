# Protocol

How icmpchat moves a message: the sender, the listener, the wire format, encryption, and the relay. The [README](../README.md) covers install and usage.

## Sender (unprivileged)

Sends over a `SOCK_DGRAM` ICMP socket (`"udp4"`). The kernel rewrites the ICMP
identifier, so routing relies on the payload, never on the ID. After sending, the
sender waits up to 2 s for the matching echo reply (matched by payload bytes, not
ID) and prints `✓` on delivery or `✗ (no reply)` on timeout, retrying once. The
kernel's auto-reply doubles as a free delivery acknowledgment — replies are never
crafted by hand.

## Listener (root)

Listens on a raw IPv4 ICMP socket (`"ip4:icmp"`) and filters echo requests
(type 8) whose payload starts with the 4-byte magic `ICHT` and whose source is
the peer. The IP header (delivered first on both macOS and Linux) is stripped
using the IHL field. Echo replies (type 0) and non-peer packets are ignored.

## Wire format (ICMP payload, big-endian)

```
magic[4]="ICHT" ver[1] flags[1] msgid[4] chunkIdx[1] chunkCnt[1] nameLen[1] name text
```

With `--key`, everything after the 5-byte header (`magic` + `ver`) is sealed with
AES-256-GCM and a random 12-byte nonce is prepended; the visible header lets the
listener filter without the key.

Max payload is 1000 bytes, so a message is never sent as a single oversized
packet. Longer text is split into chunks sharing a random `msgid` and reassembled
by the receiver in `chunkIdx` order.

## Encryption

`--key` derives a 32-byte key via `SHA-256(passphrase)` and seals the payload with
AES-256-GCM (stdlib `crypto/cipher`). Ciphertext that fails authentication (wrong
key or tampering) is dropped silently.

## Relay

How it works:

- Each client's outgoing chunk is wrapped in a small **visible relay header**
  (`magic ver flags roomLen room`) in front of the (possibly encrypted) chat
  payload. The header stays unencrypted so the relay can route without the key.
- The relay parses the header, records the sender as a member of the room, and
  queues the chat payload for every *other* member of that room.
- Members **pull** their messages by polling the relay. Each client sends a
  short poll — an ICMP echo request carrying only the relay header with the
  poll flag set — about once a second. A poll is both a keepalive (it refreshes
  the member's TTL) and a request to drain anything queued since the last poll.
- The relay drains each member's queue and delivers the messages as ICMP echo
  **replies** (type 0), re-wrapped in a relay header with the deliver flag set
  and copied from the poll's ICMP id/seq. Queued messages go out oldest first,
  and each is delivered exactly once. The relay never crafts echo requests; it
  only answers a poll with a queued message.
- Members that go quiet are pruned after a configurable TTL.

This pull model is what makes relay mode work on macOS. The kernel answers echo
requests itself and never passes them to raw sockets, so a macOS client cannot
receive relay chat as echo requests. Echo **replies** (type 0), however, do reach
macOS raw sockets, so the relay delivers queued messages that way. Direct
`--peer` mode is unchanged and keeps the same macOS receive limitation.

### Relay wire flags

The `flags` byte after `ver`:

| Flag     | Direction        | Meaning                                            |
| -------- | ---------------- | -------------------------------------------------- |
| `0x01`   | message          | payload carries a visible relay routing header     |
| `0x02`   | client → relay   | echo request is a poll (relay header only)         |
| `0x04`   | relay → client   | echo reply carries a queued message                |

The client and relay share the wire-format, chunking, crypto, and socket logic
under `internal/icmpchat`; the relay entrypoint is `cmd/relay`.
