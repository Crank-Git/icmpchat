# Contributing

## Branch strategy and CI

- **`dev`** is the working branch; **`main`** is the stable, shipped line.
- CI runs on every push/PR to `dev` and `main`, on both macOS and Linux:
  - `gofmt` formatting check
  - `go vet`
  - `go build ./...` and `go test ./...` across both platforms
  - the e2e suite

Work is merged to `dev`, validated, then merged to `main`.

## Project layout

The client is a thin `package main` over a shared protocol package:

```
icmpchat/
├── main.go                 # client CLI (entrypoint)
├── cmd/
│   └── relay/              # relay server (one-to-many chat)
│       ├── main.go
│       └── relay_test.go
├── internal/
│   └── icmpchat/           # shared client+relay protocol/socket package
│       ├── proto.go        # wire format, chunking, crypto, reassembly
│       ├── icmpio.go       # sender + listener socket helpers
│       ├── relay_proto_test.go
│       └── (moved tests: proto, icmpio, listener, sender, integration)
├── e2e_test.go             # builds + runs the real binary
├── scripts/
│   └── e2e_remote.sh       # two-host LAN test (needs sudo)
├── .github/workflows/ci.yml
├── go.mod
└── README.md
```

The client and the relay share the wire-format, chunking, crypto, and socket
logic under `internal/icmpchat`; the client entrypoint stays at `main.go` and
the relay server lives at `cmd/relay`.
