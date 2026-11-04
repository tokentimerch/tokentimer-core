//go:build windows

package verifiedextraction

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

func TestQuarantineInspectionValidatesMarkerAndRedactsSecret(t *testing.T) {
	stage, sddl := intentFixture(t)
	first, err := stage.beginExecutionIntent(fixtureArchive, fixtureSCM, sddl, defaultIntentIO())
	if err != nil {
		t.Fatal(err)
	}
	dirHandle, err := lockQuarantineDirectory(stage.path, stage.policy)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(dirHandle)
	if err := os.WriteFile(filepath.Join(stage.path, "active-fixture"), []byte("test"), 0600); err != nil {
		t.Fatalf("inspection blocked an active writer: %v", err)
	}
	observed, err := inspectQuarantineRecord(stage)
	if err != nil || observed != first {
		t.Fatalf("inspect protected marker: %v", err)
	}
	badPolicy := &PrivateStaging{path: stage.path, identity: stage.identity, policy: bootstraplock.Policy{Owners: map[string]bool{}, Writers: map[string]bool{}}}
	if _, err := inspectQuarantineRecord(badPolicy); err == nil || strings.Contains(err.Error(), first.Secret) {
		t.Fatal("untrusted marker ACL accepted or secret leaked")
	}
	other := first
	other.StageName = "TokenTimer-Staging-" + strings.Repeat("b", 32)
	other.IndexLow++
	summary, err := summarizeQuarantinePair([]ExecutionIntent{observed, other})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(summary)
	if err != nil || strings.Contains(string(b), first.Secret) || strings.Contains(string(b), "secret") {
		t.Fatal("inspection exposed a secret")
	}
	other.Secret = strings.Repeat("c", 64)
	if _, err := summarizeQuarantinePair([]ExecutionIntent{observed, other}); err == nil {
		t.Fatal("mismatched secret accepted")
	}
	if _, err := summarizeQuarantinePair([]ExecutionIntent{observed}); err == nil {
		t.Fatal("incomplete pair accepted")
	}
	before, err := os.ReadFile(stage.path + ".intent")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage.path+".intent", []byte(`{"schemaVersion":1,"schemaVersion":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectQuarantineRecord(stage); err == nil || strings.Contains(err.Error(), first.Secret) {
		t.Fatal("invalid marker accepted or secret leaked")
	}
	if err := os.WriteFile(stage.path+".intent", before, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage.path); err != nil {
		t.Fatal("inspection removed staging")
	}
}

func TestQuarantineMarkerInventoryRefusesIncompleteAmbiguousAndMalformedSets(t *testing.T) {
	valid := func(ch string) string { return "TokenTimer-Staging-" + strings.Repeat(ch, 32) + ".intent" }
	cases := []struct {
		name  string
		files []string
		ok    bool
	}{
		{"empty", nil, false},
		{"partial", []string{valid("a")}, false},
		{"complete", []string{valid("a"), valid("b")}, true},
		{"extra", []string{valid("a"), valid("b"), valid("c")}, false},
		{"bad-suffix-case", []string{valid("a"), strings.TrimSuffix(valid("b"), ".intent") + ".INTENT"}, false},
		{"bad-prefix-case", []string{valid("a"), strings.Replace(valid("b"), "TokenTimer", "tokentimer", 1)}, false},
		{"bad-stage-name", []string{valid("a"), "TokenTimer-Staging-bad.intent"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			names, err := quarantineMarkerNames(entries)
			if (err == nil) != tc.ok || (tc.ok && len(names) != 2) {
				t.Fatalf("unexpected inventory result: %v", err)
			}
		})
	}
}
