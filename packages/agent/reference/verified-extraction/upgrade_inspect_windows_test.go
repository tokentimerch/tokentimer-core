//go:build windows

package verifiedextraction

import (
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tokentimer-verified-extraction/bootstraplock"
)

func writeProtectedUpgradeFixture(t *testing.T, f releaseFixture, b []byte) {
	t.Helper()
	if err := os.WriteFile(f.journal, b, 0600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(f.sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(f.journal, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}
func TestUpgradeInspectionIsReadOnlyAndRedactsServiceSecrets(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	root := filepath.Dir(filepath.Dir(f.journal))
	journal := []byte(`{"version":1,"pid":321,"previousIdentity":"11:22","stagingIdentity":"11:33","previousServicePath":"secret-service-path","previousServiceDisplayName":"secret-name","previousServiceStartMode":"Automatic","hadPreviousServiceEnvironment":true,"previousServiceEnvironment":["secret-value"],"launcherIntent":"` + f.txn + `"}`)
	writeProtectedUpgradeFixture(t, f, journal)
	if err := createRestrictedDirectory(filepath.Join(root, "app"), f.sddl); err != nil {
		t.Fatal(err)
	}
	systemAdmins := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	strict := bootstraplock.Policy{Owners: systemAdmins, Writers: systemAdmins}
	report, err := inspectUpgradeRecovery(root, f.parentPolicy, strict, func() (string, error) { return "running", nil })
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "ambiguous-manual-review-required" || report.ServiceState != "running" || report.Previous != "absent" || report.Application == "absent" {
		t.Fatalf("unexpected report: %+v", report)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("service data leaked")
	}
	after, err := os.ReadFile(f.journal)
	if err != nil || string(after) != string(journal) {
		t.Fatal("journal changed")
	}
}
func TestUpgradeInspectionRejectsMalformedOrMissingRecords(t *testing.T) {
	for _, tc := range []struct{ name, content string }{{"missing", ""}, {"malformed", "{"}, {"duplicate", `{"version":1,"version":1}`}, {"foreign", `{"version":1,"launcherIntent":"invalid"}`}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			if tc.content != "" {
				writeProtectedUpgradeFixture(t, f, []byte(tc.content))
			}
			root := filepath.Dir(filepath.Dir(f.journal))
			if _, err := inspectUpgradeRecovery(root, f.parentPolicy, f.stagePolicy, func() (string, error) { return "running", nil }); err == nil {
				t.Fatal("unsafe journal accepted")
			}
		})
	}
}

func TestUpgradeInspectionLocksJournalDuringObservation(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	root := filepath.Dir(filepath.Dir(f.journal))
	journal := []byte(`{"version":1,"pid":321,"previousIdentity":"11:22","stagingIdentity":"11:33","previousServicePath":"private","previousServiceDisplayName":"private","previousServiceStartMode":"Manual","hadPreviousServiceEnvironment":false,"previousServiceEnvironment":[],"launcherIntent":"` + f.txn + `"}`)
	writeProtectedUpgradeFixture(t, f, journal)
	app := filepath.Join(root, "app")
	if err := createRestrictedDirectory(app, f.sddl); err != nil {
		t.Fatal(err)
	}
	_, err := inspectUpgradeRecovery(root, f.parentPolicy, f.stagePolicy, func() (string, error) {
		if err := os.Rename(app, app+".replacement"); err == nil {
			t.Error("observed app renamed during inspection")
		}
		if err := os.Remove(f.journal); err == nil {
			t.Error("journal removed during inspection")
		}
		if err := os.WriteFile(f.journal, []byte("changed"), 0600); err == nil {
			t.Error("journal changed during inspection")
		}
		if err := os.Rename(f.journal, f.journal+".replaced"); err == nil {
			t.Error("journal renamed during inspection")
		}
		return "running", nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestUpgradeInspectionRejectsUntrustedJournalACL(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	root := filepath.Dir(filepath.Dir(f.journal))
	writeProtectedUpgradeFixture(t, f, []byte(`{}`))
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(f.journal, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = inspectUpgradeRecovery(root, f.parentPolicy, f.stagePolicy, func() (string, error) { t.Fatal("service queried despite untrusted record"); return "", nil }); err == nil {
		t.Fatal("untrusted journal accepted")
	}
}

func TestUpgradeInspectionRejectsOtherOperatorSID(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("f", 32))
	root := filepath.Dir(filepath.Dir(f.journal))
	writeProtectedUpgradeFixture(t, f, []byte(`{}`))
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	other := "S-1-5-21-999-999-999-1234"
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + current.User.Sid.String() + ")(A;;FA;;;" + other + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(f.journal, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	strict := bootstraplock.Policy{Owners: trusted, Writers: trusted}
	if _, err = inspectUpgradeRecovery(root, f.parentPolicy, strict, func() (string, error) { t.Fatal("untrusted SID reached SCM"); return "", nil }); err == nil {
		t.Fatal("other operator SID accepted")
	}
}

func TestClassifyUpgradePresenceDoesNotAuthorizeRecovery(t *testing.T) {
	for _, tc := range []struct{ app, previous, staging, want string }{
		{"1:1", "1:2", "absent", "app-and-backup-present-unverified"},
		{"1:1", "absent", "1:3", "app-and-staging-present-unverified"},
		{"absent", "1:2", "1:3", "backup-and-staging-present-unverified"},
		{"1:1", "1:2", "1:3", "ambiguous-manual-review-required"},
		{"1:1", "absent", "absent", "ambiguous-manual-review-required"},
		{"absent", "absent", "absent", "ambiguous-manual-review-required"},
		{"", "1:2", "1:3", "ambiguous-manual-review-required"},
	} {
		if got := classifyUpgradePresence(tc.app, tc.previous, tc.staging); got != tc.want {
			t.Errorf("layout %+v: got %s", tc, got)
		}
	}
}
func TestUpgradeInspectionAcceptsLegacyAndRejectsUnknownContractFields(t *testing.T) {
	for _, extra := range []struct {
		name, suffix string
		ok           bool
	}{{"legacy", "", true}, {"unknown contract field", `,"identityContract":{"scheme":"node-fs-win32-v1","unexpected":"x"}`, false}} {
		t.Run(extra.name, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			root := filepath.Dir(filepath.Dir(f.journal))
			journal := []byte(`{"version":1,"pid":321,"previousIdentity":"11:22","stagingIdentity":"11:33","previousServicePath":"private","previousServiceDisplayName":"private","previousServiceStartMode":"Manual","hadPreviousServiceEnvironment":false,"previousServiceEnvironment":[],"launcherIntent":"` + f.txn + `"` + extra.suffix + `}`)
			writeProtectedUpgradeFixture(t, f, journal)
			_, err := inspectUpgradeRecovery(root, f.parentPolicy, f.stagePolicy, func() (string, error) { return "running", nil })
			if (err == nil) != extra.ok {
				t.Fatalf("unexpected inspection result: %v", err)
			}
		})
	}
}
