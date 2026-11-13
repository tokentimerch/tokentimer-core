//go:build windows && registrycredentialexperiment && credentialpipeexperiment

package verifiedextraction

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestBoundRotationFrameRejectsUnknownCommands(t *testing.T) {
	for _, input := range []string{`{"command":"ack"}`, `{"command":"bound-read","binding":null}`, `{"command":"bound-read","command":"bound-read"}`} {
		var output bytes.Buffer
		if err := runBoundRotationFrame(0, nil, strings.NewReader(input), &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid command accepted")
		}
	}
}

func TestBoundRotationFrameRealRegistry(t *testing.T) {
	if os.Getenv("TT_ROTATION_SYSTEM_TEST") != "1" {
		t.Skip("requires SYSTEM laboratory fixture")
	}
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, boundRotationKey) })
	want := testBoundState()
	if err := initializeBoundRotation(parent, sddl, trusted, want); err != nil {
		t.Fatal(err)
	}
	makeRequest := func(binding rotationBinding) []byte {
		b, err := json.Marshal(map[string]any{"command": "bound-read", "binding": binding})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var out bytes.Buffer
	if err := runBoundRotationFrame(parent, trusted, bytes.NewReader(makeRequest(want.Binding)), &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Credential string `json:"credential"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.Credential != want.State.Active {
		t.Fatal("credential unavailable")
	}
	wrong := want.Binding
	wrong.WorkspaceID = "33333333-3333-4333-8333-333333333333"
	out.Reset()
	if err := runBoundRotationFrame(parent, trusted, bytes.NewReader(makeRequest(wrong)), &out); err == nil || out.Len() != 0 {
		t.Fatal("mismatched workspace accepted")
	}
}
