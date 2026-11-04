//go:build windows

package verifiedextraction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This explicitly opted-in test creates protected directories under the real
// Program Files root. Run only in a disposable elevated Windows lab VM.
// It does not invoke the installer or modify any existing quarantine.
func TestPreInvokeCleanupElevatedNative(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires elevated administrator or SYSTEM token")
	}
	if os.Getenv("TT_TEST_ELEVATED_PREINVOKE") != "1" {
		t.Skip("set TT_TEST_ELEVATED_PREINVOKE=1 only on a disposable Windows lab VM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release, err := beginInstallGuard(ctx)
	if err != nil {
		t.Fatalf("existing recovery or install guard unavailable: %v", err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Errorf("release install guard: %v", err)
		}
	}()
	p, err := NewPrivateStaging()
	if err != nil {
		t.Fatalf("create payload stage: %v", err)
	}
	defer p.Close()
	s, err := NewPrivateStaging()
	if err != nil {
		if e := p.Cleanup(); e != nil {
			t.Logf("payload retained at %s: %v", p.path, e)
		}
		t.Fatalf("create scratch stage: %v", err)
	}
	defer s.Close()
	done := false
	defer func() {
		if !done {
			t.Logf("fixture retained for investigation: %s and %s", p.path, s.path)
		}
	}()
	for _, stage := range []*PrivateStaging{p, s} {
		if err := os.WriteFile(filepath.Join(stage.Root(), "fixture.txt"), []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := stage.LockPayload(); err != nil {
			t.Fatalf("lock payload: %v", err)
		}
	}
	const sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	a, err := p.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, defaultIntentIO())
	if err != nil {
		t.Fatalf("payload intent: %v", err)
	}
	if _, err := s.beginExecutionIntentForTransaction(fixtureArchive, fixtureSCM, sddl, a.Transaction, a.Secret, defaultIntentIO()); err != nil {
		t.Fatalf("scratch intent: %v", err)
	}
	bad := a
	bad.Transaction = "invalid"
	if err := abortBeforeInvocation(p, s, bad); err == nil {
		t.Fatal("mismatched transaction accepted")
	}
	for _, stage := range []*PrivateStaging{p, s} {
		if _, err := os.Stat(stage.path); err != nil {
			t.Fatalf("stage removed after rejected request: %v", err)
		}
		if _, err := os.Stat(stage.path + ".intent"); err != nil {
			t.Fatalf("intent removed after rejected request: %v", err)
		}
	}
	// An injected deletion failure must leave both protected markers and both
	// directories available for the same process to retry safely.
	fault := errors.New("injected stage cleanup failure")
	if err := abortBeforeInvocationWith(p, s, a, func(*PrivateStaging) error { return fault }, func(windows.Handle) error { t.Fatal("marker deletion reached after stage failure"); return nil }); !errors.Is(err, fault) {
		t.Fatalf("stage failure was not retained: %v", err)
	}
	for _, stage := range []*PrivateStaging{p, s} {
		for _, path := range []string{stage.path, stage.path + ".intent"} {
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("fixture lost after failed cleanup: %v", err)
			}
		}
	}
	if err := abortBeforeInvocation(p, s, a); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	done = true
	for _, stage := range []*PrivateStaging{p, s} {
		for _, path := range []string{stage.path, stage.path + ".intent"} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Errorf("fixture retained at %s: %v", path, err)
			}
		}
	}
}
