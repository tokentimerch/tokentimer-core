//go:build windows

package verifiedextraction

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type runFixture struct {
	beginErr, scratchErr, installErr, pathErr error
	events                                    []string
	afterScratch                              func()
}

func TestInstallerReceivesInheritedIntentPipe(t *testing.T) {
	t.Setenv("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN", "ambient-value-must-not-leak")
	for _, token := range []string{"", "fixture-token"} {
		t.Run(fmt.Sprintf("token-present-%t", token != ""), func(t *testing.T) {
			root := t.TempDir()
			script := filepath.Join(root, "pipe.ps1")
			text := fmt.Sprintf(`$ErrorActionPreference='Stop'; $h=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle([IntPtr]([int64]$env:TOKENTIMER_AGENT_INTENT_HANDLE), $true); $f=New-Object IO.FileStream($h,[IO.FileAccess]::Read,64,$false); $b=New-Object byte[] 64; $n=$f.Read($b,0,64); if ($n -ne 64 -or [Text.Encoding]::ASCII.GetString($b) -cne ('d' * 64)) { exit 71 }; if ($env:TOKENTIMER_AGENT_EXECUTION_INTENT -cne ('a' * 32)) { exit 72 }; if ([string]$env:TOKENTIMER_AGENT_BOOTSTRAP_TOKEN -cne '%s') { exit 73 }; exit 0`, token)
			if err := os.WriteFile(script, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			if err := invokeInstaller(context.Background(), script, root, nil, token, strings.Repeat("a", 32), strings.Repeat("d", 64), nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstallerDoesNotRunWhenResumeIsDenied(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "installer.ps1")
	if err := os.WriteFile(script, []byte(`[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'started'), 'yes')`), 0600); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("install guard release failed")
	err := invokeInstaller(context.Background(), script, root, nil, "", strings.Repeat("a", 32), strings.Repeat("b", 64), func() error {
		return denied
	})
	if !errors.Is(err, denied) {
		t.Fatalf("unexpected installer result: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "started")); !os.IsNotExist(err) {
		t.Fatalf("installer started after resume was denied: %v", err)
	}
}

func TestQualifiedInstallerPinRejectsOlderSignedInstaller(t *testing.T) {
	hash := strings.Repeat("a", 64)
	m := Manifest{Files: []Entry{{Path: "package/scripts/install-agent.ps1", SHA256: hash}}}
	if err := requireQualifiedInstaller(m, hash); err != nil {
		t.Fatal(err)
	}
	if err := requireQualifiedInstaller(m, strings.Repeat("b", 64)); err == nil {
		t.Fatal("unqualified installer accepted")
	}
	if err := requireQualifiedInstaller(m, ""); err == nil {
		t.Fatal("missing independent pin accepted")
	}
}

func (f *runFixture) BeginExecutionIntent(string) (ExecutionIntent, error) {
	f.events = append(f.events, "intent")
	return ExecutionIntent{Transaction: strings.Repeat("a", 32), ArchiveSHA256: strings.Repeat("b", 64), Secret: strings.Repeat("d", 64)}, f.beginErr
}
func (f *runFixture) InstallerPath() (string, error) {
	f.events = append(f.events, "installer")
	return `C:\private\install.ps1`, f.pathErr
}
func (f *runFixture) Cleanup() error { f.events = append(f.events, "cleanup"); return nil }
func (f *runFixture) Close()         { f.events = append(f.events, "close") }

type scratchFixture struct{ *runFixture }

func (f scratchFixture) Root() string { return `C:\private\scratch` }
func (f scratchFixture) BeginScratchIntent(string, string, string, string) error {
	f.events = append(f.events, "scratch-intent")
	if f.afterScratch != nil {
		f.afterScratch()
	}
	return f.scratchErr
}
func (f scratchFixture) Cleanup() error { f.events = append(f.events, "scratch-cleanup"); return nil }
func (f scratchFixture) Close()         { f.events = append(f.events, "scratch-close") }

func TestRunCandidateQuarantinesAfterIntent(t *testing.T) {
	for _, scenario := range []string{"success", "intent", "scratch", "installer", "termination-failed"} {
		t.Run(scenario, func(t *testing.T) {
			f := &runFixture{}
			if scenario == "intent" {
				f.beginErr = errors.New("intent")
			}
			if scenario == "scratch" {
				f.scratchErr = errors.New("scratch")
			}
			if scenario == "installer" {
				f.installErr = errors.New("installer")
			}
			if scenario == "termination-failed" {
				f.installErr = errors.Join(context.Canceled, errors.New("process job termination failed"))
			}
			deps := executionDependencies{
				nativeArch: func() (string, error) { return runtime.GOARCH, nil },
				prepare:    func(Candidate) (preparedForRun, error) { return f, nil },
				scratch:    func() (scratchForRun, error) { return scratchFixture{f}, nil },
				beginGuard: func(context.Context) (func() error, error) {
					f.events = append(f.events, "guard")
					return func() error { f.events = append(f.events, "release"); return nil }, nil
				},
				scmDigest: func() (string, error) { return strings.Repeat("c", 64), nil },
				invoke: func(_ context.Context, _, _ string, _ []string, _, tx, secret string, beforeResume func() error) error {
					if err := beforeResume(); err != nil {
						return err
					}
					f.events = append(f.events, "invoke")
					if tx != strings.Repeat("a", 32) {
						t.Fatal("missing transaction")
					}
					if secret != strings.Repeat("d", 64) {
						t.Fatal("missing secret")
					}
					return f.installErr
				},
			}
			res, err := runCandidate(context.Background(), Candidate{Architecture: runtime.GOARCH}, nil, "", deps)
			if !res.CleanupPending {
				t.Fatal("expected quarantine")
			}
			joined := strings.Join(f.events, ",")
			if strings.Contains(joined, "cleanup") || !strings.Contains(joined, "scratch-close,close") {
				t.Fatalf("unsafe cleanup %s", joined)
			}
			if scenario == "success" && (err != nil || res.InstallerErr != nil || !strings.Contains(joined, "installer,release,invoke")) {
				t.Fatalf("unexpected result: %v %v %s", err, res.InstallerErr, joined)
			}
			if scenario == "intent" || scenario == "scratch" {
				if err == nil || strings.Contains(joined, "invoke") {
					t.Fatalf("unsafe invocation: %v %s", err, joined)
				}
			}
			if (scenario == "installer" || scenario == "termination-failed") && (err != nil || res.InstallerErr == nil) {
				t.Fatalf("lost installer status: %v %v", err, res.InstallerErr)
			}
		})
	}
}

func TestRunCandidateCancelledBeforeInvocationCleansFreshPair(t *testing.T) {
	f := &runFixture{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps := executionDependencies{
		nativeArch: func() (string, error) { return runtime.GOARCH, nil },
		prepare:    func(Candidate) (preparedForRun, error) { return f, nil },
		scratch:    func() (scratchForRun, error) { return scratchFixture{f}, nil },
		beginGuard: func(context.Context) (func() error, error) {
			return func() error { f.events = append(f.events, "release"); return nil }, nil
		},
		scmDigest: func() (string, error) { return strings.Repeat("c", 64), nil },
		invoke: func(context.Context, string, string, []string, string, string, string, func() error) error {
			t.Fatal("installer invoked after cancellation")
			return nil
		},
		abortBeforeInvoke: func(preparedForRun, scratchForRun, ExecutionIntent) error {
			f.events = append(f.events, "abort")
			return nil
		},
	}
	f.afterScratch = cancel
	result, err := runCandidate(ctx, Candidate{Architecture: runtime.GOARCH}, nil, "", deps)
	if !errors.Is(err, context.Canceled) || result.CleanupPending {
		t.Fatalf("unexpected result: %+v %v", result, err)
	}
	if strings.Join(f.events, ",") != "intent,scratch-intent,abort,release" {
		t.Fatalf("unexpected events: %v", f.events)
	}
}

func TestRunCandidateHoldsStagingWhileFailedTerminationWaits(t *testing.T) {
	f := &runFixture{}
	done := make(chan error, 1)
	reported := make(chan struct{}, 1)
	result := make(chan RunResult, 1)
	runErr := make(chan error, 1)
	terminationErr := errors.New("termination failure")
	deps := executionDependencies{
		nativeArch: func() (string, error) { return runtime.GOARCH, nil },
		prepare:    func(Candidate) (preparedForRun, error) { return f, nil },
		scratch:    func() (scratchForRun, error) { return scratchFixture{f}, nil },
		beginGuard: func(context.Context) (func() error, error) {
			return func() error { f.events = append(f.events, "release"); return nil }, nil
		},
		scmDigest: func() (string, error) { return strings.Repeat("c", 64), nil },
		invoke: func(_ context.Context, _, _ string, _ []string, _, _, _ string, beforeResume func() error) error {
			if err := beforeResume(); err != nil {
				return err
			}
			return waitCanceledChild(context.Canceled, done, func() error { return terminationErr }, func() { reported <- struct{}{} })
		},
	}
	go func() {
		r, err := runCandidate(context.Background(), Candidate{Architecture: runtime.GOARCH}, nil, "", deps)
		result <- r
		runErr <- err
	}()
	select {
	case <-reported:
	case <-time.After(5 * time.Second):
		t.Fatal("termination failure was not reported")
	}
	if events := strings.Join(f.events, ","); strings.Contains(events, "close") || strings.Contains(events, "cleanup") {
		t.Fatalf("staging released while the child is still running: %s", events)
	}
	select {
	case <-result:
		t.Fatal("launcher returned while the child is still running")
	default:
	}
	done <- nil
	select {
	case r := <-result:
		if err := <-runErr; err != nil || !r.CleanupPending || !errors.Is(r.InstallerErr, context.Canceled) || !errors.Is(r.InstallerErr, terminationErr) {
			t.Fatalf("unexpected result: %+v, %v", r, err)
		}
		if events := strings.Join(f.events, ","); strings.Contains(events, "cleanup") || !strings.Contains(events, "scratch-close,close") {
			t.Fatalf("staging was not retained: %s", events)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("launcher did not finish after child exit")
	}
}

func TestRunCandidateSetupFailureCleansFreshPairUnderGuard(t *testing.T) {
	f := &runFixture{}
	setupErr := errors.New("suspended installer setup failed")
	held := false
	deps := executionDependencies{
		nativeArch: func() (string, error) { return runtime.GOARCH, nil },
		prepare:    func(Candidate) (preparedForRun, error) { return f, nil },
		scratch:    func() (scratchForRun, error) { return scratchFixture{f}, nil },
		beginGuard: func(context.Context) (func() error, error) {
			held = true
			return func() error { held = false; return nil }, nil
		},
		scmDigest: func() (string, error) { return strings.Repeat("c", 64), nil },
		invoke: func(context.Context, string, string, []string, string, string, string, func() error) error {
			return setupErr
		},
		abortBeforeInvoke: func(preparedForRun, scratchForRun, ExecutionIntent) error {
			if !held {
				t.Fatal("setup failure cleaned after releasing the guard")
			}
			f.events = append(f.events, "abort")
			return nil
		},
	}
	result, err := runCandidate(context.Background(), Candidate{Architecture: runtime.GOARCH}, nil, "", deps)
	if err != nil || !errors.Is(result.InstallerErr, setupErr) || result.CleanupPending ||
		!strings.Contains(strings.Join(f.events, ","), "abort") || held {
		t.Fatalf("setup failure did not clear the fresh intent pair: %+v %v %v", result, err, f.events)
	}
}

// No installer process exists on this path; clean only while the guard is held.
func TestRunCandidatePathFailureAbortsOnlyUnderGuard(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup-fails-%t", cleanupFails), func(t *testing.T) {
			f := &runFixture{pathErr: errors.New("path unavailable")}
			held := false
			deps := executionDependencies{
				nativeArch: func() (string, error) { return runtime.GOARCH, nil },
				prepare:    func(Candidate) (preparedForRun, error) { return f, nil },
				scratch:    func() (scratchForRun, error) { return scratchFixture{f}, nil },
				beginGuard: func(context.Context) (func() error, error) {
					held = true
					return func() error { held = false; f.events = append(f.events, "release"); return nil }, nil
				},
				scmDigest: func() (string, error) { return strings.Repeat("c", 64), nil },
				invoke: func(context.Context, string, string, []string, string, string, string, func() error) error {
					t.Fatal("installer invoked")
					return nil
				},
				abortBeforeInvoke: func(preparedForRun, scratchForRun, ExecutionIntent) error {
					if !held {
						t.Fatal("guard not held")
					}
					f.events = append(f.events, "abort")
					if cleanupFails {
						return errors.New("cleanup failed")
					}
					return nil
				},
			}
			result, err := runCandidate(context.Background(), Candidate{Architecture: runtime.GOARCH}, nil, "", deps)
			if err == nil || result.CleanupPending != cleanupFails {
				t.Fatalf("unexpected result: %+v %v", result, err)
			}
			events := strings.Join(f.events, ",")
			if cleanupFails && (!strings.Contains(events, "scratch-close,close") || strings.Contains(events, "cleanup")) {
				t.Fatalf("quarantine not retained: %s", events)
			}
			if !cleanupFails && events != "intent,scratch-intent,installer,abort,release" {
				t.Fatalf("unexpected events: %s", events)
			}
		})
	}
}
