# icmpchat

Terminal chat whose messages travel inside the payload of **ICMP Echo Request**
packets. Type at a `> ` prompt; your text is carried in an ICMP echo, delivered
to the peer, and acknowledged by the kernel's echo reply.

Single Go binary, one dependency group (`golang.org/x/net`), optional AES-256-GCM
encryption from the standard library.

[![CI](https://github.com/Crank-Git/icmpchat/actions/workflows/ci.yml/badge.svg)](https://github.com/Crank-Git/icmpchat/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.26-00add8.svg)](go.mod)

## Features

- **Zero-agent transport** — chat over plain ICMP echo; nothing to run on the peer.
- **Unprivileged send** — the sender uses a `SOCK_DGRAM` ICMP socket and needs no root.
- **Free delivery ack** — the kernel's echo reply doubles as a delivery
  confirmation; the sender prints `✓` or `✗ (no reply)`.
- **Optional encryption** — `--key` seals payloads with AES-256-GCM.
- **Long messages** — anything over ~1000 bytes is chunked and reassembled
  automatically.
- **Optional relay** — a relay server enables one-to-many chat and decouples
  peers (see [Roadmap](#roadmap)).

## Build

```sh
go build -o icmpchat .
```

## Usage

```sh
icmpchat --peer <ip> [--name <nick>] [--key <passphrase>]
```

| Flag       | Description                                        | Default  |
| ---------- | -------------------------------------------------- | -------- |
| `--peer`   | Peer IP address (required).                        | —        |
| `--name`   | Your display name.                                 | `anon`   |
| `--key`    | Optional passphrase; enables AES-256-GCM encryption. | —      |

```sh
$ icmpchat --peer 192.0.2.10 --name alice
icmpchat: chatting as "alice", peer 192.0.2.10
payload encryption: off
> hi there
✓
```

Incoming messages print on their own line above the prompt:

```
[14:03:07] bob: on you
```

### Receiving requires root

The **receiving** side listens for incoming echo requests on a raw ICMP socket,
which needs root. Run without sudo and icmpchat prints a clear message and
continues in **send-only** mode:

```
receiving needs root: run with sudo (could not open raw ICMP socket: ...: operation not permitted)
running in send-only mode; enable receiving with sudo.
```

To chat between two hosts, each side runs its receiver as root:

```sh
# on host A
sudo icmpchat --peer 192.168.1.221 --name alice
# on host B
sudo icmpchat --peer 192.168.1.133 --name bob
```

> macOS blocks incoming echo requests behind the firewall by default. Allow
> incoming requests in *System Settings → Network → Firewall → Options* (or
> disable the firewall) so the raw listener sees peers' echo requests.

## How it works

### Sender (unprivileged)

Sends over a `SOCK_DGRAM` ICMP socket (`"udp4"`). The kernel rewrites the ICMP
identifier, so routing relies on the payload, never on the ID. After sending, the
sender waits up to 2 s for the matching echo reply (matched by payload bytes, not
ID) and prints `✓` on delivery or `✗ (no reply)` on timeout, retrying once. The
kernel's auto-reply doubles as a free delivery acknowledgment — replies are never
crafted by hand.

### Listener (root)

Listens on a raw IPv4 ICMP socket (`"ip4:icmp"`) and filters echo requests
(type 8) whose payload starts with the 4-byte magic `ICHT` and whose source is
the peer. The IP header (delivered first on both macOS and Linux) is stripped
using the IHL field. Echo replies (type 0) and non-peer packets are ignored.

### Wire format (ICMP payload, big-endian)

```
magic[4]="ICHT" ver[1] flags[1] msgid[4] chunkIdx[1] chunkCnt[1] nameLen[1] name text
```

With `--key`, everything after the 5-byte header (`magic` + `ver`) is sealed with
AES-256-GCM and a random 12-byte nonce is prepended; the visible header lets the
listener filter without the key.

Max payload is 1000 bytes, so a message is never sent as a single oversized
packet. Longer text is split into chunks sharing a random `msgid` and reassembled
by the receiver in `chunkIdx` order.

### Encryption

`--key` derives a 32-byte key via `SHA-256(passphrase)` and seals the payload with
AES-256-GCM (stdlib `crypto/cipher`). Ciphertext that fails authentication (wrong
key or tampering) is dropped silently.

## Testing

```sh
go test ./...
```

Tests come in four levels:

| Level             | File(s)                                         | What it covers                                              | Needs root? |
| ----------------- | ----------------------------------------------- | ----------------------------------------------------------- | ----------- |
| Unit              | `proto_test.go`                                 | encode/decode, 5000-byte chunking, bad magic, truncation, wrong key | no |
| Integration       | `integration_test.go`                           | full wire pipeline: encode → chunk → reassemble → decode, multi-message | no |
| Socket pipeline   | `icmpio_test.go`, `listener_test.go`            | IP-header stripping, source filtering, echo-reply ignoring  | no (synthetic packets) |
| End-to-end        | `e2e_test.go`                                   | builds the real binary and runs it against 127.0.0.1        | sender only (unprivileged on macOS) |
| Remote two-host   | `scripts/e2e_remote.sh`                         | real chat between two machines over the LAN                 | **yes** |

The unit, integration, and socket-pipeline tests run anywhere. The e2e tests
build and run the actual binary and skip gracefully where an ICMP sender socket
cannot be opened (non-root on Linux). The remote two-host script exercises the
full receive path and must be run with sudo on each host.

### Remote end-to-end

The full receive path needs a raw socket (root). Run the driver on host A:

```sh
# Single-host self-delivery (validates the receive path on one host):
sudo scripts/e2e_remote.sh <this-host-lan-ip> <name>

# Two-host (run on A; drives B over ssh):
sudo scripts/e2e_remote.sh <host-b-ip> <name-a> <user@host-b>
```

It exchanges a cleartext message, a long chunked message, and an encrypted
message in both directions and verifies each delivery.

## Project layout

The client is a single flat `package main` for simplicity:

```
icmpchat/
├── main.go                 # client CLI (entrypoint)
├── icmpio.go               # sender + listener socket helpers
├── proto.go                # wire format, chunking, crypto, reassembly
├── proto_test.go           # unit tests
├── icmpio_test.go          # socket-pipeline tests (synthetic packets)
├── listener_test.go        # listener packet-handling tests
├── sender_test.go          # unprivileged loopback send test
├── integration_test.go     # full wire-pipeline integration tests
├── e2e_test.go             # builds + runs the real binary
├── scripts/
│   └── e2e_remote.sh       # two-host LAN test (needs sudo)
├── .github/workflows/ci.yml
├── go.mod
└── README.md
```

The relay (Batch 2) will be split into `cmd/relay` and shared protocol/socket
logic moved under `internal/` so the client and relay can share it.

## Branch strategy & CI

- **`dev`** is the working branch; **`main`** is the stable, shipped line.
- CI runs on every push/PR to `dev` and `main`, on both macOS and Linux:
  - `gofmt` formatting check
  - `go vet`
  - `go build ./...` and `go test ./...` across both platforms
  - the e2e suite

Work is merged to `dev`, validated, then merged to `main`.

## Known risks

- **Firewalls/NAT/cloud:** many networks rate-limit or drop ICMP, so this works
  only where the peer is reachable and ICMP is permitted — not everywhere TCP
  or UDP would.
- **Root required to receive:** the receiving side must run `sudo`, as noted
  above.
- **Not a secure or reliable transport by default:** the optional AES-GCM layer
  adds confidentiality and integrity of payload content only, not
  traffic-analysis resistance. ICMP echo traffic to a given host is still
  visible on the wire as ICMP. This is a toy/educational transport.

## Roadmap

- [x] Unprivileged sender + root listener, chunking, optional encryption
- [x] Unprivileged sender + root listener, chunking, optional encryption
- [x] Unit, integration, e2e, and remote two-host tests
- [x] GitHub repo with `dev`/`main` branches and CI
- [x] Split client/relay into `cmd/` + `internal/` packages
- [ ] Relay server for one-to-many chat and peer decoupling
- [ ] Full two-host e2e run with the relay (validated on macOS + Ubuntu)
