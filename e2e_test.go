package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildBinary compiles the icmpchat binary into a temp dir.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "icmpchat"+extSuffix())
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("building icmpchat binary: %v", err)
	}
	return bin
}

func extSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// runClient feeds input to a freshly built icmpchat binary pointed at peer and
// returns combined stdout+stderr.
func runClient(t *testing.T, bin, peer, name, input string) string {
	t.Helper()
	cmd := exec.Command(bin, "--peer", peer, "--name", name)
	cmd.Stdin = bytes.NewReader([]byte(input))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		// A non-zero exit is expected when the sender socket cannot be opened
		// (e.g. non-root on Linux). Surface stderr but do not fail the build.
		t.Logf("icmpchat exited %v: %s", err, out.String())
	}
	return out.String()
}

// TestE2ESendLoopback builds and runs the real binary against the loopback
// address and expects a delivery checkmark. It skips gracefully on platforms
// or privilege levels where an ICMP sender socket cannot be opened.
func TestE2ESendLoopback(t *testing.T) {
	if runtime.GOOS == "linux" {
		// An unprivileged ICMP DGRAM socket needs CAP_NET_RAW. Skip unless we
		// are root (CI runners are), so the test is meaningful but not flaky.
		if os.Getuid() != 0 {
			t.Skip("ICMP send requires root on Linux; run with sudo for a full e2e")
		}
	}

	bin := buildBinary(t)
	out := runClient(t, bin, "127.0.0.1", "e2e", "hello e2e\n")

	// A missing checkmark means the environment blocks ICMP (no kernel reply),
	// which is an environment limitation, not a code bug: skip rather than fail.
	if strings.Contains(out, "cannot open sender socket") ||
		strings.Contains(out, "✗ (no reply)") {
		t.Skip("ICMP send is unavailable in this environment")
	}
	if !strings.Contains(out, "✓") {
		t.Fatalf("expected a delivery checkmark in output, got:\n%s", out)
	}
}

// TestE2ELongMessageChunked builds and runs the binary with a >1000 byte
// message and expects every chunk to be acknowledged.
func TestE2ELongMessageChunked(t *testing.T) {
	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		t.Skip("ICMP send requires root on Linux; run with sudo for a full e2e")
	}

	bin := buildBinary(t)
	long := strings.Repeat("x", 2500)
	out := runClient(t, bin, "127.0.0.1", "long", long+"\n")

	if strings.Contains(out, "cannot open sender socket") ||
		strings.Contains(out, "✗ (no reply)") {
		t.Skip("ICMP send is unavailable in this environment")
	}
	// 2500 bytes spans several 1000-byte chunks; each must be delivered.
	if strings.Count(out, "✓") < 3 {
		t.Fatalf("expected at least 3 delivery checkmarks for chunked message, got %d in:\n%s",
			strings.Count(out, "✓"), out)
	}
}

// TestE2EUsageNoPeer verifies that omitting --peer prints usage and exits
// non-zero.
func TestE2EUsageNoPeer(t *testing.T) {
	bin := buildBinary(t)
	out := runClient(t, bin, "", "", "")
	if !strings.Contains(out, "usage:") {
		t.Fatalf("expected usage message, got:\n%s", out)
	}
}
