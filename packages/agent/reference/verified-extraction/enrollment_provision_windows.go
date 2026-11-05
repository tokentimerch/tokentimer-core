//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
	"tokentimer-verified-extraction/bootstraplock"
)

// Experimental fresh-enrollment building block only; not called by runtime.
// Caller must independently establish trusted installation provenance and
// absence of previous privileged work. The mutex coordinates only cooperating
// processes and does not make legacy migration safe.
func provisionFromProtectedEnrollment(ctx context.Context, dir string, policy bootstraplock.Policy, trusted map[string]bool, parent registry.Key, sddl string) error {
	return withRotationLock(ctx, func() error {
		locks, err := bootstraplock.LockAncestors(dir, policy)
		if err != nil {
			return fmt.Errorf("enrollment unavailable")
		}
		defer locks.Close()
		pendingAbsent := func() bool {
			_, err := os.Lstat(filepath.Join(dir, "registration.pending.json"))
			return os.IsNotExist(err)
		}
		if !pendingAbsent() || validateCredentialRegistryKey(parent, trusted) != nil {
			return fmt.Errorf("enrollment unavailable")
		}
		configBytes, err := readProtectedEnrollmentFile(dir, "config.json", policy, trusted, 65536)
		if err != nil {
			return fmt.Errorf("enrollment unavailable")
		}
		defer clear(configBytes)
		syntax := json.NewDecoder(bytes.NewReader(configBytes))
		if checkJSONValue(syntax, 0) != nil {
			return fmt.Errorf("enrollment unavailable")
		}
		if _, err := syntax.Token(); err != io.EOF {
			return fmt.Errorf("enrollment unavailable")
		}
		var config struct {
			AgentID      string `json:"agentId"`
			WorkspaceID  string `json:"workspaceId"`
			ServerURL    string `json:"serverUrl"`
			CABundlePath string `json:"caBundlePath"`
		}
		if json.Unmarshal(configBytes, &config) != nil || !strings.EqualFold(filepath.Clean(config.CABundlePath), filepath.Join(dir, "ca-bundle.pem")) {
			return fmt.Errorf("enrollment unavailable")
		}
		ca, err := readProtectedEnrollmentFile(dir, "ca-bundle.pem", policy, trusted, 1<<20)
		if err != nil {
			return fmt.Errorf("enrollment unavailable")
		}
		defer clear(ca)
		secret, err := readProtectedEnrollmentFile(dir, "credential", policy, trusted, 512)
		if err != nil {
			return fmt.Errorf("enrollment unavailable")
		}
		defer clear(secret)
		credential := strings.TrimSpace(string(secret))
		binding, err := verifyEnrollmentIdentity(ctx, config.ServerURL, ca, credential, config.AgentID, config.WorkspaceID)
		if err != nil || ctx.Err() != nil || !pendingAbsent() {
			return fmt.Errorf("enrollment unavailable")
		}
		state := boundRotationState{Version: 3, Binding: binding, State: rotationState{Version: 2, Phase: "active", Active: credential}}
		if createBoundProvisionPending(parent, sddl, trusted, state, flushCredentialKey) != nil {
			return fmt.Errorf("enrollment unavailable")
		}
		return nil
	})
}
