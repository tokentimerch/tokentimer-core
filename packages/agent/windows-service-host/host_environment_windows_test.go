//go:build windows

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestAgentHostPreservesOtherEnvironmentEntries(t *testing.T) {
	want := []string{
		`=C:=C:\Program Files`,
		`Path=C:\Windows\System32`,
		`NODE_EXTRA_CA_CERTS=C:\pinned\ca.pem`,
		`NODE_USE_SYSTEM_CA=1`,
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
