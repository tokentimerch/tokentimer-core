//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func testRotationBinding() rotationBinding {
	return rotationBinding{ID: "11111111-1111-4111-8111-111111111111", AgentID: "agent-a", WorkspaceID: "22222222-2222-4222-8222-222222222222", Origin: "https://example.test", CAHash: strings.Repeat("a", 64)}
}

func TestBoundRotationCanonicalOriginsMatchNode(t *testing.T) {
	node, err := exec.LookPath("node.exe")
	if err != nil {
		t.Skip("node.exe unavailable")
	}
	for _, origin := range []string{"https://example.test", "https://example.test:8443", "https://127.0.0.1"} {
		binding := testRotationBinding()
		binding.Origin = origin
		if !validRotationBinding(binding) {
			t.Fatal("Go rejected expected canonical origin")
		}
		out, err := exec.Command(node, "-e", `process.stdout.write(new URL(process.argv[1]).origin)`, origin).Output()
		if err != nil || string(out) != origin {
			t.Fatalf("origin differs from Node: %s", origin)
		}
	}
}
func testBoundState() boundRotationState {
	return boundRotationState{Version: 3, Binding: testRotationBinding(), State: rotationState{Version: 2, Phase: "active", Active: registryFixtureRecord().Credential}}
}

func TestBoundRotationRejectsMalformedBinding(t *testing.T) {
	good := testRotationBinding()
	if !validRotationBinding(good) {
		t.Fatal("valid binding rejected")
	}
	for _, alter := range []func(*rotationBinding){
		func(b *rotationBinding) { b.ID = "bad" }, func(b *rotationBinding) { b.WorkspaceID = "bad" }, func(b *rotationBinding) { b.AgentID = "bad/id" },
		func(b *rotationBinding) { b.CAHash = "" }, func(b *rotationBinding) { b.CAHash = strings.Repeat("A", 64) },
		func(b *rotationBinding) { b.Origin = "http://example.test" }, func(b *rotationBinding) { b.Origin = "https://EXAMPLE.test" },
		func(b *rotationBinding) { b.Origin = "https://example.test:443" }, func(b *rotationBinding) { b.Origin = "https://example.test/path" },
		func(b *rotationBinding) { b.Origin = "https://user@example.test" }, func(b *rotationBinding) { b.Origin = "https://example.test?x=1" },
		func(b *rotationBinding) { b.Origin = "https://example.test:0443" }, func(b *rotationBinding) { b.Origin = "https://example.test:65536" },
		func(b *rotationBinding) { b.Origin = "https://127.1" }, func(b *rotationBinding) { b.Origin = "https://[2001:0db8::1]" },
		func(b *rotationBinding) { b.Origin = "https://[::ffff:192.0.2.1]" },
		func(b *rotationBinding) { b.Origin = "https://[2001:db8::1]" }, func(b *rotationBinding) { b.Origin = "https://[::1]:8443" },
		func(b *rotationBinding) { b.Origin = "https://xn--bcher-kva.example" }, func(b *rotationBinding) { b.Origin = "https://bücher.example" },
	} {
		b := good
		alter(&b)
		if validRotationBinding(b) {
			t.Fatal("ambiguous binding accepted")
		}
	}
	for _, origin := range []string{"https://example.test:8443", "https://127.0.0.1"} {
		b := good
		b.Origin = origin
		if !validRotationBinding(b) {
			t.Fatalf("canonical origin rejected: %s", origin)
		}
	}
}

func TestBoundRotationTransitionsPreserveBinding(t *testing.T) {
	if os.Getenv("TT_ROTATION_SYSTEM_TEST") != "1" {
		t.Skip("requires SYSTEM laboratory fixture")
	}
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, boundRotationKey) })
	initial := testBoundState()
	if err := lockedInitializeBoundRotation(context.Background(), parent, sddl, trusted, initial); err != nil {
		t.Fatal(err)
	}
	prepared := initial
	prepared.State.Phase = "prepared"
	prepared.State.Operation = strings.Repeat("b", 32)
	prepared.State.Candidate = "ttagent_" + strings.Repeat("d", 16) + "_" + strings.Repeat("e", 64)
	changed := prepared
	changed.Binding.WorkspaceID = "33333333-3333-4333-8333-333333333333"
	if err := lockedTransitionBoundRotation(context.Background(), parent, trusted, initial, changed); err == nil {
		t.Fatal("workspace replacement accepted")
	}
	if err := lockedTransitionBoundRotation(context.Background(), parent, trusted, initial, prepared); err != nil {
		t.Fatal(err)
	}
	if err := lockedTransitionBoundRotation(context.Background(), parent, trusted, prepared, prepared); err != nil {
		t.Fatal(err)
	}
	if credential, err := boundStartupCredential(context.Background(), parent, trusted, initial.Binding); err == nil || credential != "" {
		t.Fatal("unfinished state exposed credential")
	}
	committed := prepared
	committed.State.Phase = "committed"
	if err := lockedTransitionBoundRotation(context.Background(), parent, trusted, prepared, committed); err != nil {
		t.Fatal(err)
	}
	promoted := committed
	promoted.State.Phase = "promoted"
	promoted.State.Active = committed.State.Candidate
	promoted.State.Candidate = ""
	if err := lockedTransitionBoundRotation(context.Background(), parent, trusted, committed, promoted); err != nil {
		t.Fatal(err)
	}
	cleared := promoted
	cleared.State.Phase = "active"
	cleared.State.Operation = ""
	if err := lockedTransitionBoundRotation(context.Background(), parent, trusted, promoted, cleared); err == nil {
		t.Fatal("acknowledgement receipt erased")
	}
}

func TestBoundRotationPreservesAndFlushesIdentity(t *testing.T) {
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, boundRotationKey) })
	want := testBoundState()
	if err := initializeBoundRotation(parent, sddl, trusted, want); err != nil {
		t.Fatal(err)
	}
	if err := initializeBoundRotation(parent, sddl, trusted, want); err == nil {
		t.Fatal("existing state overwritten")
	}
	k, err := registry.OpenKey(parent, boundRotationKey, registry.QUERY_VALUE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	got, err := readBoundRotation(k, trusted, flushCredentialKey)
	if err != nil || got != want {
		t.Fatal("binding recovery failed")
	}
	got, err = readBoundRotation(k, trusted, func(registry.Key) error { return errors.New("flush failure") })
	if err == nil || got != (boundRotationState{}) {
		t.Fatal("flush failure exposed state")
	}
}

func TestBoundRotationRefusesExistingV2(t *testing.T) {
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() {
		_ = registry.DeleteKey(parent, rotationStateKey)
		_ = registry.DeleteKey(parent, boundRotationKey)
	})
	if err := initializeRotationState(parent, sddl, trusted, registryFixtureRecord().Credential); err != nil {
		t.Fatal(err)
	}
	if err := initializeBoundRotation(parent, sddl, trusted, testBoundState()); err == nil {
		t.Fatal("unbound state migrated")
	}
}

func TestBoundRotationStartupRequiresMatchingContext(t *testing.T) {
	if os.Getenv("TT_ROTATION_SYSTEM_TEST") != "1" {
		t.Skip("requires SYSTEM laboratory fixture")
	}
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, boundRotationKey) })
	want := testBoundState()
	if err := lockedInitializeBoundRotation(context.Background(), parent, sddl, trusted, want); err != nil {
		t.Fatal(err)
	}
	got, err := boundStartupCredential(context.Background(), parent, trusted, want.Binding)
	if err != nil || got != want.State.Active {
		t.Fatal("matching context rejected")
	}
	for _, alter := range []func(*rotationBinding){func(b *rotationBinding) { b.ID = "33333333-3333-4333-8333-333333333333" }, func(b *rotationBinding) { b.AgentID = "agent-b" }, func(b *rotationBinding) { b.WorkspaceID = "44444444-4444-4444-8444-444444444444" }, func(b *rotationBinding) { b.Origin = "https://other.test" }, func(b *rotationBinding) { b.CAHash = strings.Repeat("b", 64) }} {
		b := want.Binding
		alter(&b)
		got, err = boundStartupCredential(context.Background(), parent, trusted, b)
		if err == nil || got != "" {
			t.Fatal("mismatched context exposed credential")
		}
	}
}
