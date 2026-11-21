//go:build windows

package main

import (
	"reflect"
	"testing"
)

// Constructor-only tests: no child process, native API or SCM call occurs.
func TestNewAgentHostFiltersPreloadEnvironment(t *testing.T) {
	input := []string{"PATH=C:\\Windows", "NODE_OPTIONS=--require=untrusted", "node_options=--import=untrusted", "Node_Path=C:\\untrusted", "NODE_USE_SYSTEM_CA=1", "NODE_EXTRA_CA_CERTS=C:\\public-ca.pem", "OTHER=preserved"}
	want := []string{input[0], input[4], input[5], input[6]}
	host := newAgentHost("unused-node.exe", []string{"--use-system-ca", "agent.js"}, input, nil)
	if !reflect.DeepEqual(host.env, want) {
		t.Fatalf("unexpected child environment: %v", host.env)
	}
	input[0] = "PATH=changed-after-construction"
	if host.env[0] != want[0] {
		t.Fatal("child environment aliases caller storage")
	}
	if !reflect.DeepEqual(host.childArgs, []string{"--use-system-ca", "agent.js"}) {
		t.Fatal("explicit CA arguments changed")
	}
}

func TestNewAgentHostFiltersInheritedEnvironment(t *testing.T) {
	t.Setenv("NODE_OPTIONS", "--require=untrusted")
	t.Setenv("NODE_PATH", "C:\\untrusted")
	t.Setenv("NODE_USE_SYSTEM_CA", "0")
	host := newAgentHost("unused-node.exe", nil, nil, nil)
	for _, value := range host.env {
		if value == "NODE_OPTIONS=--require=untrusted" || value == "NODE_PATH=C:\\untrusted" {
			t.Fatal("inherited preload environment was preserved")
		}
	}
	if len(host.env) == 0 {
		t.Fatal("ordinary inherited environment was lost")
	}
	empty := newAgentHost("unused-node.exe", nil, []string{}, nil)
	if empty.env == nil || len(empty.env) != 0 {
		t.Fatal("explicit empty environment must remain empty")
	}
}
