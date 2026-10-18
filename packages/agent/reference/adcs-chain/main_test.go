package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsageExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != exitFail {
		t.Fatalf("exit %d, want %d", code, exitFail)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr missing usage: %q", stderr.String())
	}
}

// Invalid/mixed modes must not silently invoke chain validation or a metadata
// scan with an incomplete exclusion identity.
func TestKeySurvivorCLIAdmission(t *testing.T) {
	for _, args := range [][]string{
		{"--key-survivors"},
		{"--key-survivors", "--container", "tokentimer-owned", "--exclude-store", "My"},
		{"--key-survivors", "--container", "tokentimer-owned", "--exclude-store", "", "--exclude-thumbprint", ""},
		{"--container", "tokentimer-owned"},
		{"--key-survivors", "--container", "foreign", "--exclude-store", "My", "--exclude-thumbprint", strings.Repeat("A", 40)},
		{"--key-survivors", "--container", "tokentimer-owned", "--exclude-store", "My", "--exclude-thumbprint", strings.Repeat("A", 40), "--cert", "some-file"},
	} {
		var stdout, stderr bytes.Buffer
		if run(args, &stdout, &stderr) != exitFail {
			t.Fatal("invalid metadata mode accepted")
		}
		if stdout.Len() != 0 {
			t.Fatal("invalid mode produced apparent evidence")
		}
	}
}
