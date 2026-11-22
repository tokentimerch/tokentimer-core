//go:build windows && azurecmsqualify

package main

import (
	"strings"
	"testing"
)

func TestToolRequiresAcknowledgementAndEmbeddedPolicy(t *testing.T) {
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
		t.Fatalf("missing acknowledgement: %v", err)
	}
	if err := run([]string{"-experimental"}); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("missing embedded policy: %v", err)
	}
}
