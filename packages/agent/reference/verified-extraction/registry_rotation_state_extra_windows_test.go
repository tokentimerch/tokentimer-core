//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestRotationStateCancelledWaitDoesNotRun(t *testing.T) {
	if os.Getenv("TT_ROTATION_SYSTEM_TEST") != "1" {
		t.Skip("requires SYSTEM laboratory fixture")
	}
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withRotationLock(context.Background(), func() error { close(held); <-release; return nil })
	}()
	<-held
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan struct{}, 1)
	waiting := make(chan error, 1)
	go func() { waiting <- withRotationLock(ctx, func() error { called <- struct{}{}; return nil }) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-waiting; err == nil {
		t.Fatal("cancelled lock succeeded")
	}
	select {
	case <-called:
		t.Fatal("cancelled operation executed")
	default:
	}
}

func TestRotationStateCASChild(t *testing.T) {
	path, suffix := os.Getenv("TT_ROTATION_CAS_PATH"), os.Getenv("TT_ROTATION_CAS_SUFFIX")
	if path == "" {
		return
	}
	if suffix != "d" && suffix != "e" {
		os.Exit(2)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		os.Exit(2)
	}
	parent, err := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS|windows.READ_CONTROL)
	if err != nil {
		os.Exit(2)
	}
	defer parent.Close()
	active := registryFixtureRecord().Credential
	expected := rotationState{Version: 2, Phase: "active", Active: active}
	next := rotationState{Version: 2, Phase: "prepared", Active: active, Operation: strings.Repeat(suffix, 32), Candidate: "ttagent_" + strings.Repeat(suffix, 16) + "_" + strings.Repeat(suffix, 64)}
	err = lockedRotationTransition(context.Background(), parent, map[string]bool{user.User.Sid.String(): true}, expected, next)
	if err != nil {
		if strings.Contains(err.Error(), "changed or unavailable") {
			os.Exit(3)
		}
		os.Exit(2)
	}
}

func TestRotationStateConcurrentCASProcesses(t *testing.T) {
	if os.Getenv("TT_ROTATION_SYSTEM_TEST") != "1" {
		t.Skip("requires SYSTEM laboratory fixture")
	}
	parent, sddl, trusted, path := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, rotationStateKey) })
	if err := lockedRotationInitialize(context.Background(), parent, sddl, trusted, registryFixtureRecord().Credential); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]*exec.Cmd, 2)
	for i, suffix := range []string{"d", "e"} {
		cmd := exec.Command(exe, "-test.run=^TestRotationStateCASChild$")
		cmd.Env = append(os.Environ(), "TT_ROTATION_CAS_PATH="+path, "TT_ROTATION_CAS_SUFFIX="+suffix)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands[i] = cmd
	}
	codes := map[int]int{}
	for _, cmd := range commands {
		code := 0
		if err := cmd.Wait(); err != nil {
			e, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			code = e.ExitCode()
		}
		codes[code]++
	}
	if codes[0] != 1 || codes[3] != 1 {
		t.Fatalf("expected one CAS winner, exit codes: %v", codes)
	}
	state, err := lockedRotationRead(context.Background(), parent, trusted)
	if err != nil || state.Phase != "prepared" || (state.Operation != strings.Repeat("d", 32) && state.Operation != strings.Repeat("e", 32)) {
		t.Fatal("winner not recovered")
	}
}

func TestRotationStateAbandonMutexChild(t *testing.T) {
	if os.Getenv("TT_ROTATION_ABANDON") != "1" {
		return
	}
	_ = withRotationLock(context.Background(), func() error { os.Exit(0); return nil })
	os.Exit(2)
}

func TestRotationStateAbandonedMutexRecovery(t *testing.T) {
	if os.Getenv("TT_ROTATION_SYSTEM_TEST") != "1" {
		t.Skip("requires SYSTEM laboratory fixture")
	}
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() { _ = registry.DeleteKey(parent, rotationStateKey) })
	if err := lockedRotationInitialize(context.Background(), parent, sddl, trusted, registryFixtureRecord().Credential); err != nil {
		t.Fatal(err)
	}
	// Keep a handle to the same named object, otherwise Windows can delete it
	// when the child exits and a new mutex would not report abandonment.
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(rotationMutexName)
	h, err := windows.CreateMutex(&attrs, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := validateInstallMutex(h); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestRotationStateAbandonMutexChild$")
	cmd.Env = append(os.Environ(), "TT_ROTATION_ABANDON=1")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	state, err := lockedRotationRead(context.Background(), parent, trusted)
	if err != nil || state.Phase != "active" || state.Active != registryFixtureRecord().Credential {
		t.Fatal("abandoned state not recovered")
	}
}
