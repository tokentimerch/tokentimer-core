//go:build windows

package verifiedextraction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type runFixture struct {
	beginErr, scratchErr, installErr error
	events                           []string
}

func TestInstallerReceivesInheritedIntentPipe(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "pipe.ps1")
	text := `$ErrorActionPreference='Stop'; $h=[Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]::new([long]$env:TOKENTIMER_AGENT_INTENT_HANDLE),$false); $f=[IO.FileStream]::new($h,[IO.FileAccess]::Read); $b=New-Object byte[] 64; $n=$f.Read($b,0,64); if ($n -ne 64 -or [Text.Encoding]::ASCII.GetString($b) -cne ('d' * 64)) { exit 71 }; if ($env:TOKENTIMER_AGENT_EXECUTION_INTENT -cne ('a' * 32)) { exit 72 }; exit 0`
	if err := os.WriteFile(script, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err := invokeInstaller(context.Background(), script, root, nil, "", strings.Repeat("a", 32), strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
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
	return `C:\private\install.ps1`, nil
}
func (f *runFixture) Cleanup() error { f.events = append(f.events, "cleanup"); return nil }
func (f *runFixture) Close()         { f.events = append(f.events, "close") }

type scratchFixture struct{ *runFixture }

func (f scratchFixture) Root() string { return `C:\private\scratch` }
func (f scratchFixture) BeginScratchIntent(string, string, string, string) error {
	f.events = append(f.events, "scratch-intent")
	return f.scratchErr
}
func (f scratchFixture) Cleanup() error { f.events = append(f.events, "scratch-cleanup"); return nil }
func (f scratchFixture) Close()         { f.events = append(f.events, "scratch-close") }

func TestRunCandidateQuarantinesAfterIntent(t *testing.T) {
	for _, scenario := range []string{"success", "intent", "scratch", "installer"} {
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
			deps := executionDependencies{
				nativeArch: func() (string, error) { return runtime.GOARCH, nil },
				prepare:    func(Candidate) (preparedForRun, error) { return f, nil },
				scratch:    func() (scratchForRun, error) { return scratchFixture{f}, nil },
				beginGuard: func(context.Context) (func() error, error) {
					f.events = append(f.events, "guard")
					return func() error { f.events = append(f.events, "release"); return nil }, nil
				},
				scmDigest: func() (string, error) { return strings.Repeat("c", 64), nil },
				invoke: func(_ context.Context, _, _ string, _ []string, _, tx, secret string) error {
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
			if scenario == "success" && (err != nil || res.InstallerErr != nil || !strings.Contains(joined, "release,installer,invoke")) {
				t.Fatalf("unexpected result: %v %v %s", err, res.InstallerErr, joined)
			}
			if scenario == "intent" || scenario == "scratch" {
				if err == nil || strings.Contains(joined, "invoke") {
					t.Fatalf("unsafe invocation: %v %s", err, joined)
				}
			}
			if scenario == "installer" && (err != nil || res.InstallerErr == nil) {
				t.Fatalf("lost installer status: %v %v", err, res.InstallerErr)
			}
		})
	}
}
