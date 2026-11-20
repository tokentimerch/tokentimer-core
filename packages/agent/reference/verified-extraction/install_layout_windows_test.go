//go:build windows

package verifiedextraction

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAssertNoPendingExecution(t *testing.T) {
	for _, tc := range []struct {
		name        string
		directories []string
		file        string
	}{
		{name: "absent installs"},
		{name: "existing installs without journals", directories: []string{
			`ProgramData\TokenTimerAgent\state`, `Program Files\TokenTimerAgent\state`,
		}},
		{name: "legacy journal", file: `ProgramData\TokenTimerAgent\state\upgrade-recovery.json`},
		{name: "bundled journal", file: `Program Files\TokenTimerAgent\state\upgrade-recovery.json`},
		{name: "legacy root collision", file: `ProgramData\TokenTimerAgent`},
		{name: "bundled state collision", file: `Program Files\TokenTimerAgent\state`},
		{name: "quarantine marker", file: `Program Files\TokenTimer-Staging-11111111111111111111111111111111.intent`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			programFiles := filepath.Join(root, "Program Files")
			legacyRoot := filepath.Join(root, "ProgramData", "TokenTimerAgent")
			if err := os.Mkdir(programFiles, 0700); err != nil {
				t.Fatal(err)
			}
			for _, dir := range tc.directories {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.file != "" {
				path := filepath.Join(root, tc.file)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := assertNoPendingExecution(programFiles, legacyRoot)
			if tc.file == "" && err != nil {
				t.Fatalf("clean paths were refused: %v", err)
			}
			if tc.file != "" && !errors.Is(err, ErrExecutionRecoveryPending) {
				t.Fatalf("want pending recovery, got %v", err)
			}
		})
	}
}

func TestAssertNoUpgradeJournalRejectsLinkedState(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "state")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := assertNoUpgradeJournal(root); !errors.Is(err, ErrExecutionRecoveryPending) {
		t.Fatalf("want linked recovery state refused, got %v", err)
	}
}
