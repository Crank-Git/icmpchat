# Testing

```sh
go test ./...
```

Tests come in six levels:

| Level             | File(s)                                         | What it covers                                              | Needs root? |
| ----------------- | ----------------------------------------------- | ----------------------------------------------------------- | ----------- |
| Unit              | `proto_test.go`                                 | encode/decode, 5000-byte chunking, bad magic, truncation, wrong key | no |
| Integration       | `integration_test.go`                           | full wire pipeline: encode → chunk → reassemble → decode, multi-message | no |
| Socket pipeline   | `icmpio_test.go`, `listener_test.go`            | IP-header stripping, source filtering, echo-reply ignoring  | no (synthetic packets) |
| Relay routing     | `cmd/relay/relay_test.go`                       | room membership, target selection, stale-member pruning      | no |
| End-to-end        | `e2e_test.go`                                   | builds the real binary and runs it against 127.0.0.1        | sender only (unprivileged on macOS) |
| Remote two-host   | `scripts/e2e_remote.sh`                         | real chat between two machines over the LAN                 | **yes** |

The unit, integration, and socket-pipeline tests run anywhere. The e2e tests
build and run the actual binary and skip gracefully where an ICMP sender socket
cannot be opened (non-root on Linux). The remote two-host script exercises the
full receive path and must be run with sudo on each host.

## Remote end-to-end

The full receive path needs a raw socket (root). Run the driver on host A:

```sh
# Single-host self-delivery (validates the receive path on one host):
sudo scripts/e2e_remote.sh <this-host-lan-ip> <name>

# Two-host (run on A; drives B over ssh):
sudo scripts/e2e_remote.sh <host-b-ip> <name-a> <user@host-b>
```

It exchanges a cleartext message, a long chunked message, and an encrypted
message in both directions and verifies each delivery.
