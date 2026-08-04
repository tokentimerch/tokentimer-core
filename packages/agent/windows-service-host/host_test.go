//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// nodeExe resolves the node.exe on PATH once per test binary run, skipping
// every test in this file if Node is unavailable (this module has no
// dependency on Node existing, but the behavior under test - graceful
// shutdown of a Node child - is meaningless to verify without it).
func nodeExe(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found on PATH; skipping agentHost lifecycle tests")
	}
	return p
}

// mockAgentPath returns the absolute path to testdata/mock-agent.js, a
// throwaway Node script that behaves like the real agent only in the one
// way these tests care about: it stays running until asked to stop, and
// it exits promptly and cleanly on SIGBREAK (the same signal
// stopGracefully delivers via CTRL_BREAK_EVENT), mirroring
// packages/agent/src/index.js's own SIGINT/SIGTERM/SIGBREAK handling.
func mockAgentPath(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", "mock-agent.js"))
	if err != nil {
		t.Fatalf("resolve mock-agent.js path: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("mock-agent.js not found at %s: %v", abs, err)
	}
	return abs
}

func newTestLogger(t *testing.T) *hostLogger {
	t.Helper()
	return &hostLogger{out: &testWriter{t: t}}
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

func TestResolveStopTimeout(t *testing.T) {
	cases := map[string]struct {
		env  map[string]string
		want time.Duration
	}{
		"absent":      {env: map[string]string{}, want: defaultStopTimeout},
		"empty":       {env: map[string]string{stopTimeoutEnvVar: ""}, want: defaultStopTimeout},
		"non-numeric": {env: map[string]string{stopTimeoutEnvVar: "not-a-number"}, want: defaultStopTimeout},
		"zero":        {env: map[string]string{stopTimeoutEnvVar: "0"}, want: defaultStopTimeout},
		"negative":    {env: map[string]string{stopTimeoutEnvVar: "-5"}, want: defaultStopTimeout},
		"valid":       {env: map[string]string{stopTimeoutEnvVar: "1500"}, want: 1500 * time.Millisecond},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := resolveStopTimeout(func(key string) string { return tc.env[key] })
			if got != tc.want {
				t.Fatalf("resolveStopTimeout() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAgentHostGracefulStop is the core regression test for this whole
// package: it proves a child started under CREATE_NEW_PROCESS_GROUP
// actually receives and acts on the CTRL_BREAK_EVENT stopGracefully sends,
// rather than always falling through to the force-kill path (which would
// "work" for this test too, but would mean the agent's own outbox/lease
// drain on SIGBREAK never runs in production).
func TestAgentHostGracefulStop(t *testing.T) {
	node := nodeExe(t)
	entry := mockAgentPath(t)
	log := newTestLogger(t)
	host := newAgentHost(node, []string{entry}, os.Environ(), log)

	if err := host.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := host.pid()
	if pid == 0 {
		t.Fatal("expected a non-zero child pid after start")
	}

	// Give the child a moment to install its SIGBREAK handler before
	// signaling it, matching how a real agent would already be past
	// startup by the time SCM ever asks it to stop.
	time.Sleep(500 * time.Millisecond)

	stopStart := time.Now()
	if err := host.stopGracefully(5 * time.Second); err != nil {
		t.Fatalf("stopGracefully: %v", err)
	}
	elapsed := time.Since(stopStart)

	// mock-agent.js waits 500ms after SIGBREAK before exiting; a
	// force-kill (the failure mode this test exists to catch) would
	// instead return in well under 100ms because Kill() does not wait for
	// any child-side cleanup at all. The lower bound below is what
	// distinguishes "the child shut itself down" from "we just killed it
	// immediately after signaling."
	if elapsed < 300*time.Millisecond {
		t.Fatalf("stopGracefully returned in %s, too fast to be the child's own 500ms graceful "+
			"shutdown; the CTRL_BREAK_EVENT was likely never delivered and this fell through to force-kill", elapsed)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("stopGracefully took %s, suspiciously close to the 5s timeout; likely fell through to force-kill", elapsed)
	}

	select {
	case <-host.exited:
	default:
		t.Fatal("expected agentHost.exited to be closed after stopGracefully returns")
	}
}

// TestAgentHostForceKillOnTimeout proves the other half of the contract:
// a child that ignores the graceful signal is still terminated, and
// stopGracefully still returns, within a bounded time.
func TestAgentHostForceKillOnTimeout(t *testing.T) {
	node := nodeExe(t)
	log := newTestLogger(t)
	// This script ignores SIGBREAK entirely (no handler registered) and
	// just runs forever, standing in for an agent that failed to drain.
	stubbornScript := filepath.Join(t.TempDir(), "stubborn.js")
	// Node's default action for an unhandled CTRL_BREAK_EVENT is to let
	// Windows terminate the process outright, which would trivially
	// "pass" this test for the wrong reason (immediate termination looks
	// identical to a fast graceful exit). Registering a SIGBREAK listener
	// that does nothing suppresses that default action while still never
	// calling process.exit(), which is what actually exercises the
	// timeout-then-force-kill path this test targets.
	stubbornSrc := "process.on('SIGBREAK', () => {}); setInterval(() => {}, 1000);\n"
	if err := os.WriteFile(stubbornScript, []byte(stubbornSrc), 0o600); err != nil {
		t.Fatalf("write stubborn script: %v", err)
	}
	host := newAgentHost(node, []string{stubbornScript}, os.Environ(), log)
	if err := host.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	stopStart := time.Now()
	if err := host.stopGracefully(1 * time.Second); err != nil {
		t.Fatalf("stopGracefully: %v", err)
	}
	elapsed := time.Since(stopStart)
	if elapsed < 1*time.Second {
		t.Fatalf("stopGracefully returned in %s, before its own 1s timeout should have elapsed", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("stopGracefully took %s to force-kill an unresponsive child; force-kill should be near-immediate once the timeout fires", elapsed)
	}
}

// TestAgentHostWaitObservesUnrequestedExit proves the service handler's
// crash-detection path: wait() returns as soon as the child exits on its
// own, with no stop ever requested.
func TestAgentHostWaitObservesUnrequestedExit(t *testing.T) {
	node := nodeExe(t)
	log := newTestLogger(t)
	quickExitScript := filepath.Join(t.TempDir(), "quick-exit.js")
	if err := os.WriteFile(quickExitScript, []byte("process.exit(3);\n"), 0o600); err != nil {
		t.Fatalf("write quick-exit script: %v", err)
	}
	host := newAgentHost(node, []string{quickExitScript}, os.Environ(), log)
	if err := host.start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- host.wait() }()

	select {
	case err := <-waitDone:
		if err == nil {
			t.Fatal("expected a non-nil error for a child that exited with code 3")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wait() did not observe the child's own exit within 5s")
	}
}
