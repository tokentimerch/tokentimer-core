//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Experimental verification only: caller must obtain expected values, CA,
// and bearer from independently protected enrollment inputs. A successful
// response is not a quiescence barrier and cannot authorize migration or ACK.
func verifyEnrollmentIdentity(ctx context.Context, origin string, ca []byte, credential, agentID, workspaceID string) (rotationBinding, error) {
	var empty rotationBinding
	if len(ca) == 0 || len(ca) > 1<<20 || !registryCredentialPattern.MatchString(credential) || !boundAgent.MatchString(agentID) || !boundUUID.MatchString(workspaceID) {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	digest := sha256.Sum256(ca)
	probe := rotationBinding{ID: "11111111-1111-4111-8111-111111111111", AgentID: agentID, WorkspaceID: workspaceID, Origin: origin, CAHash: hex.EncodeToString(digest[:])}
	if !validRotationBinding(probe) {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/api/v1/certops/agent/credential-rotation/identity", bytes.NewReader([]byte("{}")))
	if err != nil {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := client.Do(req)
	if err != nil {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(b) == 0 || len(b) > 4096 {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	defer clear(b)
	syntax := json.NewDecoder(bytes.NewReader(b))
	if checkJSONValue(syntax, 0) != nil {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	if _, err := syntax.Token(); err != io.EOF {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	var identity struct {
		ID          string `json:"id"`
		AgentID     string `json:"agentId"`
		WorkspaceID string `json:"workspaceId"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&identity) != nil || !boundUUID.MatchString(identity.ID) || identity.AgentID != agentID || identity.WorkspaceID != workspaceID {
		return empty, fmt.Errorf("enrollment identity unavailable")
	}
	probe.ID = identity.ID
	return probe, nil
}

// Experimental transaction. Inputs must already come from a protected,
// independently authenticated enrollment; it does not prove that an older
// SYSTEM process has stopped. No runtime command invokes this function.
func provisionVerifiedBinding(ctx context.Context, parent registry.Key, sddl string, trusted map[string]bool, origin string, ca []byte, credential, agentID, workspaceID string) error {
	return withRotationLock(ctx, func() error {
		return provisionVerifiedBindingLocked(ctx, parent, sddl, trusted, origin, ca, credential, agentID, workspaceID)
	})
}

func provisionVerifiedBindingLocked(ctx context.Context, parent registry.Key, sddl string, trusted map[string]bool, origin string, ca []byte, credential, agentID, workspaceID string) error {
	if validateCredentialRegistryKey(parent, trusted) != nil {
		return fmt.Errorf("enrollment identity unavailable")
	}
	binding, err := verifyEnrollmentIdentity(ctx, origin, ca, credential, agentID, workspaceID)
	if err != nil || ctx.Err() != nil {
		return fmt.Errorf("enrollment identity unavailable")
	}
	state := boundRotationState{Version: 3, Binding: binding, State: rotationState{Version: 2, Phase: "active", Active: credential}}
	if createBoundProvisionPending(parent, sddl, trusted, state, flushCredentialKey) != nil {
		return fmt.Errorf("enrollment identity unavailable")
	}
	return nil
}
