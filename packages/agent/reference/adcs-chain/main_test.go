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
