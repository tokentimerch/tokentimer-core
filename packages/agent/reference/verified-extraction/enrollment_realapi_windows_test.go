//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// A harness starts the actual API against a disposable migrated DB and writes
// only synthetic credential material to stdin; never use production secrets.
func TestEnrollmentAgainstRealAPI(t *testing.T) {
	if os.Getenv("TT_ENROLLMENT_REAL_API_TEST") != "1" {
		t.Skip("requires isolated API and database fixture")
	}
	var fixture struct {
		Origin      string `json:"origin"`
		CA          string `json:"ca"`
		Credential  string `json:"credential"`
		AgentID     string `json:"agentId"`
		WorkspaceID string `json:"workspaceId"`
		RowID       string `json:"rowId"`
	}
	if json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&fixture) != nil {
		t.Fatal("fixture unavailable")
	}
	result, err := verifyEnrollmentIdentity(context.Background(), fixture.Origin, []byte(fixture.CA), fixture.Credential, fixture.AgentID, fixture.WorkspaceID)
	if err != nil || result.ID != fixture.RowID || result.AgentID != fixture.AgentID || result.WorkspaceID != fixture.WorkspaceID {
		t.Fatal("API identity verification failed")
	}
	wrong := "33333333-3333-4333-8333-333333333333"
	if fixture.WorkspaceID == wrong {
		wrong = "44444444-4444-4444-8444-444444444444"
	}
	if got, err := verifyEnrollmentIdentity(context.Background(), fixture.Origin, []byte(fixture.CA), fixture.Credential, fixture.AgentID, wrong); err == nil || got != (rotationBinding{}) {
		t.Fatal("workspace substitution accepted")
	}
	// The real mutex requires SYSTEM; this test exercises the same transaction
	// body against an isolated real registry key and never authorizes startup.
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() {
		_ = registry.DeleteKey(parent, boundProvisionPendingKey)
		_ = registry.DeleteKey(parent, boundRotationKey)
	})
	if err := provisionVerifiedBindingLocked(context.Background(), parent, sddl, trusted, fixture.Origin, []byte(fixture.CA), fixture.Credential, fixture.AgentID, wrong); err == nil {
		t.Fatal("workspace substitution staged")
	}
	if ensureNoBoundProvisionPending(parent) != nil {
		t.Fatal("unverified identity created state")
	}
	if err := provisionVerifiedBindingLocked(context.Background(), parent, sddl, trusted, fixture.Origin, []byte(fixture.CA), fixture.Credential, fixture.AgentID, fixture.WorkspaceID); err != nil {
		t.Fatal("verified staging failed")
	}
	pending, err := readBoundProvisionPending(parent, trusted, flushCredentialKey)
	if err != nil || pending.Binding.ID != fixture.RowID || pending.Binding.WorkspaceID != fixture.WorkspaceID || pending.State.Active != fixture.Credential {
		t.Fatal("bound pending state mismatch")
	}
	if ensureNoBoundProvisionPending(parent) == nil {
		t.Fatal("pending state failed to block startup")
	}
}
