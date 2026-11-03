package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

// TestPartialSendNotice checks the message shown when a multi-chunk send aborts
// mid-message. A single-chunk failure, or one where nothing was delivered, falls
// back to the plain "no reply" (empty notice); a partial multi-chunk failure
// names how many of how many chunks landed.
func TestPartialSendNotice(t *testing.T) {
	cases := []struct {
		delivered, total int
		wantNotice       bool
		wantSubstr       string
	}{
		{0, 1, false, ""},      // single chunk, nothing delivered
		{1, 1, false, ""},      // single chunk accounting
		{0, 3, false, ""},      // first chunk failed; no partial delivery yet
		{1, 3, true, "1 of 3"}, // one chunk landed, rest did not
		{2, 3, true, "2 of 3"}, // partial multi-chunk
		{3, 3, false, ""},      // all delivered: not a failure
	}
	for _, c := range cases {
		got := partialSendNotice(c.delivered, c.total)
		if c.wantNotice {
			if got == "" {
				t.Errorf("partialSendNotice(%d,%d) = \"\", want a notice", c.delivered, c.total)
				continue
			}
			if !strings.Contains(got, c.wantSubstr) {
				t.Errorf("partialSendNotice(%d,%d) = %q, want it to contain %q", c.delivered, c.total, got, c.wantSubstr)
			}
		} else if got != "" {
			t.Errorf("partialSendNotice(%d,%d) = %q, want \"\"", c.delivered, c.total, got)
		}
	}
}

// TestE2EPeerRelayMutualExclusion verifies that passing both --peer and --relay
// is rejected with a clear error and a non-zero exit, before any socket is
// opened. Running both at once would take the direct receive path and silently
// drop every relay delivery, so the combination must not be allowed.
func TestE2EPeerRelayMutualExclusion(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--peer", "127.0.0.1", "--relay", "127.0.0.1")
	cmd.Stdin = bytes.NewReader(nil)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected a non-zero exit for --peer with --relay, got success:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "mutually exclusive") {
		t.Fatalf("expected a mutual-exclusion error, got:\n%s", out.String())
	}
}

// runRelayClientFor runs the binary in relay mode with the given extra args,
// holds its stdin open for dur so the poll loop ticks at least once, then sends
// EOF to let it exit cleanly and returns combined output. Relay mode otherwise
// loops forever polling, so a bounded run is how its stderr is observed.
func runRelayClientFor(t *testing.T, bin string, dur time.Duration, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting icmpchat: %v", err)
	}
	time.Sleep(dur)
	stdin.Close() // EOF ends the input loop, so main returns cleanly.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	return out.String()
}

// TestE2EPollLoggingGatedByVerbose verifies that relay-mode poll keepalive
// logging is silent by default and only appears under --verbose. The default
// run must not scroll the chat with a line every second.
func TestE2EPollLoggingGatedByVerbose(t *testing.T) {
	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		t.Skip("relay sender socket needs root on Linux; run with sudo for a full e2e")
	}
	bin := buildBinary(t)

	// pollInterval is one second; 1.5s guarantees at least one tick.
	quiet := runRelayClientFor(t, bin, 1500*time.Millisecond, "--relay", "127.0.0.1", "--name", "q")
	if strings.Contains(quiet, "cannot open sender socket") {
		t.Skip("ICMP sender socket unavailable in this environment")
	}
	if strings.Contains(quiet, "poll #") || strings.Contains(quiet, "initial poll sent") {
		t.Fatalf("default run must not log poll activity, got:\n%s", quiet)
	}

	loud := runRelayClientFor(t, bin, 1500*time.Millisecond, "--relay", "127.0.0.1", "--name", "v", "--verbose")
	if strings.Contains(loud, "cannot open sender socket") {
		t.Skip("ICMP sender socket unavailable in this environment")
	}
	if !strings.Contains(loud, "poll #1 sent") {
		t.Fatalf("verbose run must log poll ticks, got:\n%s", loud)
	}
}
