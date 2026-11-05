//go:build windows && registrycredentialexperiment && credentialpipeexperiment

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Read-only and disabled in ordinary builds. Enrollment/provisioning must
// have established the binding independently; no IPC command creates it.
func RunExperimentalBoundRotation(input io.Reader, output io.Writer) error {
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	lease, err := openRegistryParent(registry.LOCAL_MACHINE, []string{"SOFTWARE", "TokenTimer", "AgentCredentialJournal"}, trusted)
	if err != nil {
		return fmt.Errorf("rotation binding unavailable")
	}
	defer lease.Close()
	return runBoundRotationFrame(lease.handles[len(lease.handles)-1], trusted, input, output)
}

func runBoundRotationFrame(parent registry.Key, trusted map[string]bool, input io.Reader, output io.Writer) error {
	b, err := io.ReadAll(io.LimitReader(input, 1025))
	if err != nil || len(b) == 0 || len(b) > 1024 {
		return fmt.Errorf("invalid bound rotation request")
	}
	defer clear(b)
	syntax := json.NewDecoder(bytes.NewReader(b))
	if checkJSONValue(syntax, 0) != nil {
		return fmt.Errorf("invalid bound rotation request")
	}
	if _, err := syntax.Token(); err != io.EOF {
		return fmt.Errorf("invalid bound rotation request")
	}
	var request struct {
		Command string           `json:"command"`
		Binding *rotationBinding `json:"binding"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || request.Command != "bound-read" || request.Binding == nil || !validRotationBinding(*request.Binding) {
		return fmt.Errorf("invalid bound rotation request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	credential, err := boundStartupCredential(ctx, parent, trusted, *request.Binding)
	if err != nil {
		return fmt.Errorf("rotation binding unavailable")
	}
	return json.NewEncoder(output).Encode(struct {
		Credential string `json:"credential"`
	}{credential})
}
