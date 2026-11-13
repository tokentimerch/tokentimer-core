//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// A process handle proves creation, not that Node has installed its signal
// handlers. Cold Windows runners can spend seconds starting Node. The fixture
// publishes readiness only after registering SIGBREAK, so shutdown assertions
// below still measure the actual handler/timeout paths rather than startup.
func readyChildEnvironment(t *testing.T) ([]string, string) {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "signal-handler-ready")
	return append(os.Environ(), "TOKENTIMER_HOST_TEST_READY_FILE="+ready), ready
}

func waitForChildReady(t *testing.T, host *agentHost, ready string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if value, err := os.ReadFile(ready); err == nil && string(value) == "ready\n" {
			return
		}
		select {
		case <-host.exited:
			t.Fatalf("child exited before installing its signal handler: %v", host.wait())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = host.stopGracefully(time.Second)
	t.Fatal("child did not publish signal-handler readiness within 15 seconds")
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

func TestAgentHostPreservesOtherEnvironmentEntries(t *testing.T) {
	want := []string{
		`=C:=C:\Program Files`,
		`Path=C:\Windows\System32`,
		`NODE_EXTRA_CA_CERTS=C:\pinned\ca.pem`,
		`NODE_PATH_SUFFIX=keep=literal`,
		`TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=fixture`,
	}
	env := append(slices.Clone(want), "NODE_OPTIONS=first", "node_options=second", "NODE_PATH=", "nOdE_pAtH=third")
	got := newAgentHost("node.exe", nil, env, nil).env
	if !slices.Equal(got, want) {
		t.Fatalf("child environment = %v, want %v", got, want)
	}
	if len(env) != len(want)+4 || env[len(want)] != "NODE_OPTIONS=first" {
		t.Fatal("source environment was changed")
	}
}

func TestAgentHostFiltersEffectiveNodeEnvironment(t *testing.T) {
	node := nodeExe(t)
	dir := t.TempDir()
	entry := filepath.Join(dir, "inspect-env.js")
	preload := filepath.Join(dir, "preload.js")
	marker := filepath.Join(dir, "preload-executed")
	if err := os.WriteFile(preload, []byte(`require("node:fs").writeFileSync(process.env.TT_HOST_TEST_PRELOAD_MARKER, "ran")`), 0o600); err != nil {
		t.Fatal(err)
	}
	source := `
const assert = require("node:assert/strict");
const keys = Object.keys(process.env).map((key) => key.toUpperCase());
assert.equal(keys.includes("NODE_OPTIONS"), false);
assert.equal(keys.includes("NODE_PATH"), false);
assert.equal(process.env.TOKENTIMER_AGENT_CONFIG_DIR, process.argv[2]);
assert.equal(process.env.NODE_OPTIONS_SUFFIX, "keep=literal");
assert.ok(process.env.SystemRoot);
`
	if err := os.WriteFile(entry, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("nOdE_OpTiOnS", `--require "`+filepath.ToSlash(preload)+`"`)
	t.Setenv("NoDe_PaTh", dir)
	t.Setenv("TT_HOST_TEST_PRELOAD_MARKER", marker)
	t.Setenv("TOKENTIMER_AGENT_CONFIG_DIR", dir)
	t.Setenv("NODE_OPTIONS_SUFFIX", "keep=literal")
	host := newAgentHost(node, []string{entry, dir}, nil, newTestLogger(t))
	if err := host.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case <-host.exited:
		default:
			_ = host.cmd.Process.Kill()
		}
	})
	select {
	case <-host.exited:
		if err := host.wait(); err != nil {
			t.Errorf("inspect Node environment: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Node environment fixture did not exit")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("Node preload marker exists or could not be inspected: %v", err)
	}
}

func TestPreparedServiceUsesVerifiedOriginInNode(t *testing.T) {
	node := nodeExe(t)
	entry := filepath.Join(t.TempDir(), "origin.js")
	const inherited = "https://inherited.invalid"
	const prepared = "https://prepared.invalid:4443"
	source := `
const assert = require("node:assert/strict");
assert.equal(process.argv.length, 4);
assert.equal(process.env.TOKENTIMER_AGENT_SERVER_URL, process.argv[2]);
assert.equal(process.env.TOKENTIMER_AGENT_ALLOW_INSECURE_LOCAL_HTTP, process.argv[3]);
assert.equal(process.env.TOKENTIMER_AGENT_SERVER_URL_SUFFIX, "neighbor=value");
assert.equal(process.env.TOKENTIMER_AGENT_CA_BUNDLE, "public fixture");
assert.equal(Object.keys(process.env).filter(key => key.toUpperCase() === "TOKENTIMER_AGENT_SERVER_URL").length, 1);
`
	if err := os.WriteFile(entry, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "tokentimer_agent_server_url="+inherited,
		"tokentimer_agent_allow_insecure_local_http=false",
		"TOKENTIMER_AGENT_SERVER_URL_SUFFIX=neighbor=value", "TOKENTIMER_AGENT_CA_BUNDLE=public fixture")
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"ordinary", []string{node, entry, inherited, "false"}},
		{"prepared", []string{preparedServerFlag, prepared, node, entry, prepared, "false"}},
		{"prepared IPv4 loopback", []string{preparedServerFlag, "http://127.0.0.2:4400", node, entry, "http://127.0.0.2:4400", "true"}},
		{"prepared IPv6 loopback", []string{preparedServerFlag, "http://[::1]:4400", node, entry, "http://[::1]:4400", "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			childArgs, childEnv, err := parseHostLaunch(tc.args, env)
			if err != nil {
				t.Fatal(err)
			}
			host := newAgentHost(childArgs[0], childArgs[1:], childEnv, newTestLogger(t))
			if err := host.start(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-host.exited:
				if err := host.wait(); err != nil {
					t.Fatal(err)
				}
			case <-time.After(15 * time.Second):
				_ = host.cmd.Process.Kill()
				t.Fatal("Node origin fixture did not exit")
			}
		})
	}
}

func TestPreparedServiceRefusesInvalidOriginArgument(t *testing.T) {
	for _, args := range [][]string{
		{preparedServerFlag},
		{preparedServerFlag, "https://prepared.invalid"},
		{preparedServerFlag, "", "node.exe"},
		{preparedServerFlag, "https://prepared.invalid/path", "node.exe"},
		{preparedServerFlag, "https://user@prepared.invalid", "node.exe"},
		{preparedServerFlag, "https://prepared.invalid?", "node.exe"},
		{preparedServerFlag, "https://prepared.invalid#", "node.exe"},
		{preparedServerFlag, "http://remote.invalid", "node.exe"},
	} {
		if _, _, err := parseHostLaunch(args, nil); err == nil {
			t.Fatalf("accepted malformed prepared host arguments: %v", args)
		}
	}
}

func TestPreparedServerFlagIsReservedOnlyBeforeTheChild(t *testing.T) {
	args := []string{"node.exe", "entry.js", preparedServerFlag, "https://child-argument.invalid"}
	env := []string{serverURLEnv + "=https://ordinary.invalid"}
	gotArgs, gotEnv, err := parseHostLaunch(args, env)
	if err != nil || !slices.Equal(gotArgs, args) || !slices.Equal(gotEnv, env) {
		t.Fatalf("ordinary child arguments or environment changed: %v, %v, %v", gotArgs, gotEnv, err)
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
	env, ready := readyChildEnvironment(t)
	host := newAgentHost(node, []string{entry}, env, log)

	if err := host.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := host.pid()
	if pid == 0 {
		t.Fatal("expected a non-zero child pid after start")
	}

	waitForChildReady(t, host, ready)

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
	if err := host.wait(); err != nil {
		t.Fatalf("child did not exit cleanly after its graceful handler: %v", err)
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
	// This script consumes SIGBREAK without exiting and keeps running,
	// standing in for an agent that failed to drain.
	stubbornScript := filepath.Join(t.TempDir(), "stubborn.js")
	// Node's default action for an unhandled CTRL_BREAK_EVENT is to let
	// Windows terminate the process outright, which would trivially
	// "pass" this test for the wrong reason (immediate termination looks
	// identical to a fast graceful exit). Registering a SIGBREAK listener
	// that does nothing suppresses that default action while still never
	// calling process.exit(), which is what actually exercises the
	// timeout-then-force-kill path this test targets.
	stubbornSrc := "process.on('SIGBREAK', () => {}); require('node:fs').writeFileSync(process.env.TOKENTIMER_HOST_TEST_READY_FILE, 'ready\\n'); setInterval(() => {}, 1000);\n"
	if err := os.WriteFile(stubbornScript, []byte(stubbornSrc), 0o600); err != nil {
		t.Fatalf("write stubborn script: %v", err)
	}
	env, ready := readyChildEnvironment(t)
	host := newAgentHost(node, []string{stubbornScript}, env, log)
	if err := host.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitForChildReady(t, host, ready)

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
