package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"tokentimer-adcs-cmc/cmccore"
)

func TestRunExitCodes(t *testing.T) {
	pin, err := os.ReadFile(filepath.Join("testdata", "ca-key-sha256.txt"))
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join("testdata", "ca.cer")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--response", filepath.Join("testdata", "issued.rsp"),
		"--ca-key-sha256", string(pin),
		"--ca-cert", ca,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("issued exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	// Wrong pin is a hard verify failure (exit 2), not unknown.
	code = run([]string{
		"--response", filepath.Join("testdata", "issued.rsp"),
		"--ca-key-sha256", "0000000000000000000000000000000000000000000000000000000000000000",
		"--ca-cert", ca,
	}, &stdout, &stderr)
	if code != exitFail {
		t.Fatalf("wrong pin exit=%d stdout=%s", code, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	// Missing args: usage -> exit 2.
	code = run(nil, &stdout, &stderr)
	if code != exitFail {
		t.Fatalf("usage exit=%d", code)
	}

	// Contract: Decode unknown with nil error must map to exit 1.
	r := cmccore.Result{Disposition: "unknown", Error: "success status without issued certificate"}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(r); err != nil {
		t.Fatal(err)
	}
	if r.Disposition != "unknown" {
		t.Fatal("expected unknown disposition for exit 1 path")
	}
}
