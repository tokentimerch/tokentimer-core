//go:build windows && reviewedrecoveryexperiment

package verifiedextraction

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExperimentalReviewSentinelPreservesStandardBoundary(t *testing.T) {
	f := newReleaseFixture(t, strings.Repeat("8", 32))
	records := []QuarantineRecord{{}, {}}
	standard := filepath.Join(f.parent, "standard-sentinel")
	experimental := filepath.Join(f.parent, "experimental-sentinel")
	statement := "operator-reviewed-external-actor-risk"
	if _, err := createReleaseSentinel(standard, f.sddl, f.stagePolicy, f.txn, records); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readReviewSentinel(standard, f.stagePolicy, f.txn, statement); err != nil {
		t.Fatalf("experimental reader rejected standard receipt: %v", err)
	}
	if _, err := createReviewSentinel(experimental, f.sddl, f.stagePolicy, f.txn, records, statement, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readReleaseSentinel(experimental, f.stagePolicy, f.txn); err != nil {
		t.Fatalf("standard reader rejected equivalent receipt: %v", err)
	}
	if _, _, err := readReviewSentinel(standard, f.stagePolicy, f.txn, "other-statement"); err == nil {
		t.Fatal("wrong statement accepted")
	}
	extended := filepath.Join(f.parent, "extended-sentinel")
	if _, err := createReviewSentinel(extended, f.sddl, f.stagePolicy, f.txn, records, "experimental-review", &upgradeJournalBinding{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readReleaseSentinel(extended, f.stagePolicy, f.txn); err == nil {
		t.Fatal("standard reader accepted experimental schema")
	}
}
