//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestRotationStateTransitionsAndRecovery(t *testing.T) {
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, rotationStateKey) })
	active := registryFixtureRecord().Credential
	if err := initializeRotationState(parent, sddl, trusted, active); err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(parent, rotationStateKey, registry.QUERY_VALUE|registry.SET_VALUE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	state, err := readRotationState(k, flushCredentialKey)
	if err != nil || state.Phase != "active" || state.Active != active {
		t.Fatal("active state unavailable")
	}
	prepared := rotationState{Version: 2, Phase: "prepared", Operation: strings.Repeat("a", 32), Active: active, Candidate: "ttagent_" + strings.Repeat("d", 16) + "_" + strings.Repeat("e", 64)}
	if err := transitionRotationState(k, trusted, state, prepared, flushCredentialKey); err != nil {
		t.Fatal(err)
	}
	if err := transitionRotationState(k, trusted, state, prepared, flushCredentialKey); err == nil {
		t.Fatal("stale compare accepted")
	}
	committed := prepared
	committed.Phase = "committed"
	if err := transitionRotationState(k, trusted, prepared, committed, flushCredentialKey); err != nil {
		t.Fatal(err)
	}
	promoted := rotationState{Version: 2, Phase: "promoted", Operation: prepared.Operation, Active: prepared.Candidate}
	if err := transitionRotationState(k, trusted, committed, promoted, flushCredentialKey); err != nil {
		t.Fatal(err)
	}
	got, err := readRotationState(k, flushCredentialKey)
	if err != nil || got != promoted {
		t.Fatal("promoted state unavailable")
	}
	if err := transitionRotationState(k, trusted, promoted, promoted, flushCredentialKey); err != nil {
		t.Fatal("idempotent promoted retry failed")
	}
	clearOperation := rotationState{Version: 2, Phase: "active", Active: promoted.Active}
	if err := transitionRotationState(k, trusted, promoted, clearOperation, flushCredentialKey); err == nil {
		t.Fatal("operation erased without durable acknowledgement")
	}
	got, err = readRotationState(k, flushCredentialKey)
	if err != nil || got != promoted {
		t.Fatal("promoted receipt changed")
	}
}

func TestRotationStateFlushFailureRetainsObservedState(t *testing.T) {
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, rotationStateKey) })
	active := registryFixtureRecord().Credential
	if err := initializeRotationState(parent, sddl, trusted, active); err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(parent, rotationStateKey, registry.QUERY_VALUE|registry.SET_VALUE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	current := rotationState{Version: 2, Phase: "active", Active: active}
	prepared := rotationState{Version: 2, Phase: "prepared", Operation: strings.Repeat("a", 32), Active: active, Candidate: "ttagent_" + strings.Repeat("d", 16) + "_" + strings.Repeat("e", 64)}
	committed := prepared
	committed.Phase = "committed"
	promoted := rotationState{Version: 2, Phase: "promoted", Operation: prepared.Operation, Active: prepared.Candidate}
	for _, next := range []rotationState{prepared, committed, promoted} {
		calls := 0
		flush := func(key registry.Key) error {
			calls++
			if calls == 2 {
				return errors.New("injected flush failure")
			}
			return flushCredentialKey(key)
		}
		if err := transitionRotationState(k, trusted, current, next, flush); err == nil {
			t.Fatal("failed flush reported success")
		}
		observed, err := readRotationState(k, flushCredentialKey)
		if err != nil || observed != next {
			t.Fatal("recovery failed to flush observed state")
		}
		current = observed
	}
}

func TestRotationStateWriteFailureLeavesObservedState(t *testing.T) {
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, rotationStateKey) })
	active := registryFixtureRecord().Credential
	if err := initializeRotationState(parent, sddl, trusted, active); err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(parent, rotationStateKey, registry.QUERY_VALUE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	writable, err := registry.OpenKey(parent, rotationStateKey, registry.QUERY_VALUE|registry.SET_VALUE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()
	current := rotationState{Version: 2, Phase: "active", Active: active}
	prepared := rotationState{Version: 2, Phase: "prepared", Operation: strings.Repeat("a", 32), Active: active, Candidate: "ttagent_" + strings.Repeat("d", 16) + "_" + strings.Repeat("e", 64)}
	committed := prepared
	committed.Phase = "committed"
	promoted := rotationState{Version: 2, Phase: "promoted", Operation: prepared.Operation, Active: prepared.Candidate}
	for _, next := range []rotationState{prepared, committed, promoted} {
		if err := transitionRotationState(k, trusted, current, next, flushCredentialKey); err == nil {
			t.Fatal("write without access reported success")
		}
		observed, err := readRotationState(k, flushCredentialKey)
		if err != nil || observed != current {
			t.Fatal("unexpected state after refused write")
		}
		if err := transitionRotationState(writable, trusted, current, next, flushCredentialKey); err != nil {
			t.Fatal(err)
		}
		current = next
	}
}

func TestRotationStateConcurrentInitChild(t *testing.T) {
	path := os.Getenv("TT_ROTATION_TEST_PATH")
	if path == "" {
		return
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		os.Exit(2)
	}
	sid := user.User.Sid.String()
	parent, err := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS|windows.READ_CONTROL)
	if err != nil {
		os.Exit(2)
	}
	defer parent.Close()
	err = lockedRotationInitialize(context.Background(), parent, "O:"+sid+"G:"+sid+"D:P(A;;KA;;;"+sid+")", map[string]bool{sid: true}, registryFixtureRecord().Credential)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			os.Exit(3)
		}
		os.Exit(2)
	}
}

func TestRotationStateConcurrentInitProcesses(t *testing.T) {
	if os.Getenv("TT_ROTATION_SYSTEM_TEST") != "1" {
		t.Skip("requires SYSTEM laboratory fixture")
	}
	parent, _, _, path := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, rotationStateKey) })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	commands := []*exec.Cmd{exec.Command(exe, "-test.run=^TestRotationStateConcurrentInitChild$"), exec.Command(exe, "-test.run=^TestRotationStateConcurrentInitChild$")}
	var logs [2]bytes.Buffer
	for i, cmd := range commands {
		cmd.Env = append(os.Environ(), "TT_ROTATION_TEST_PATH="+path)
		cmd.Stdout = &logs[i]
		cmd.Stderr = &logs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	codes := map[int]int{}
	for i, cmd := range commands {
		err := cmd.Wait()
		code := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != 0 && code != 3 {
			t.Fatalf("child %d failed unexpectedly: %s", i, logs[i].String())
		}
		codes[code]++
	}
	if codes[0] != 1 || codes[3] != 1 {
		t.Fatal("initialization did not produce exactly one winner")
	}
}

func TestRotationStateRejectsLegacyAndFlushFailure(t *testing.T) {
	parent, sddl, trusted, _ := registryFixture(t)
	if err := prepareRegistryCredential(parent, sddl, trusted, registryFixtureRecord()); err != nil {
		t.Fatal(err)
	}
	if err := initializeRotationState(parent, sddl, trusted, registryFixtureRecord().Credential); err == nil {
		t.Fatal("legacy state accepted")
	}
	parent2, sddl2, trusted2, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent2, rotationStateKey) })
	if err := initializeRotationState(parent2, sddl2, trusted2, registryFixtureRecord().Credential); err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(parent2, rotationStateKey, registry.QUERY_VALUE|registry.SET_VALUE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if state, err := readRotationState(k, func(registry.Key) error { return errors.New("flush failure") }); err == nil || state != (rotationState{}) {
		t.Fatal("flush failure returned a state")
	}
}
