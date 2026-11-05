//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestEnrollmentPendingMarkerSurvivesFailuresAndBlocks(t *testing.T) {
	for _, stage := range []string{"before-record", "flush-failure", "success"} {
		t.Run(stage, func(t *testing.T) {
			parent, sddl, trusted, _ := registryFixture(t)
			t.Cleanup(func() {
				_ = registry.DeleteKey(parent, boundProvisionPendingKey)
				_ = registry.DeleteKey(parent, boundRotationKey)
			})
			if ensureNoBoundProvisionPending(parent) != nil {
				t.Fatal("clean fixture rejected")
			}
			var hook func() error
			flush := flushCredentialKey
			if stage == "before-record" {
				hook = func() error { return errors.New("injected failure") }
			}
			if stage == "flush-failure" {
				flush = func(registry.Key) error { return errors.New("injected failure") }
			}
			err := createBoundProvisionPendingWithHook(parent, sddl, trusted, testBoundState(), flush, hook)
			if (stage == "success") != (err == nil) {
				t.Fatal("unexpected staging result")
			}
			if ensureNoBoundProvisionPending(parent) == nil {
				t.Fatal("pending marker disappeared")
			}
			if stage == "before-record" {
				if _, err := readBoundProvisionPending(parent, trusted, flushCredentialKey); err == nil {
					t.Fatal("incomplete marker accepted")
				}
			}
			if stage == "flush-failure" {
				if _, err := readBoundProvisionPending(parent, trusted, flushCredentialKey); err != nil {
					t.Fatal("visible record could not be reflushed")
				}
			}
			// Even if V3 exists after an uncertain promotion, the marker must block.
			if err := initializeBoundRotation(parent, sddl, trusted, testBoundState()); err != nil {
				t.Fatal(err)
			}
			if ensureNoBoundProvisionPending(parent) == nil {
				t.Fatal("uncertain promotion unblocked")
			}
			if credential, err := boundStartupCredentialLocked(parent, trusted, testBoundState().Binding); err == nil || credential != "" {
				t.Fatal("startup exposed credential with pending marker")
			}
		})
	}
}

func TestEnrollmentPromotionFlushFailureKeepsMarker(t *testing.T) {
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() {
		_ = registry.DeleteKey(parent, boundProvisionPendingKey)
		_ = registry.DeleteKey(parent, boundRotationKey)
	})
	if err := createBoundProvisionPending(parent, sddl, trusted, testBoundState(), flushCredentialKey); err != nil {
		t.Fatal(err)
	}
	err := initializeBoundRotationWithFlush(parent, sddl, trusted, testBoundState(), func(registry.Key) error { return errors.New("injected final flush failure") })
	if err == nil {
		t.Fatal("promotion flush failure reported success")
	}
	if ensureNoBoundProvisionPending(parent) == nil {
		t.Fatal("flush failure unblocked startup")
	}
	key, err := registry.OpenKey(parent, boundRotationKey, registry.QUERY_VALUE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	if state, err := readBoundRotation(key, trusted, flushCredentialKey); err != nil || state != testBoundState() {
		t.Fatal("visible V3 state not recovered")
	}
	if ensureNoBoundProvisionPending(parent) == nil {
		t.Fatal("reflush silently unblocked startup")
	}
	if credential, err := boundStartupCredentialLocked(parent, trusted, testBoundState().Binding); err == nil || credential != "" {
		t.Fatal("startup exposed credential after uncertain flush")
	}
}

func TestEnrollmentPendingCrashChild(t *testing.T) {
	path, stage := os.Getenv("TT_ENROLLMENT_CRASH_PATH"), os.Getenv("TT_ENROLLMENT_CRASH_STAGE")
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
	trusted := map[string]bool{sid: true}
	sddl := "O:" + sid + "G:" + sid + "D:P(A;;KA;;;" + sid + ")"
	flush := flushCredentialKey
	var hook func() error
	if stage == "after-promotion" {
		if initializeBoundRotation(parent, sddl, trusted, testBoundState()) != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if stage == "during-promotion" {
		_ = initializeBoundRotationWithFlush(parent, sddl, trusted, testBoundState(), func(registry.Key) error { os.Exit(0); return nil })
		os.Exit(2)
	}
	if stage == "created" {
		hook = func() error { os.Exit(0); return nil }
	} else if stage == "before-flush" {
		flush = func(registry.Key) error { os.Exit(0); return nil }
	} else {
		os.Exit(2)
	}
	_ = createBoundProvisionPendingWithHook(parent, sddl, trusted, testBoundState(), flush, hook)
	os.Exit(2)
}

func TestEnrollmentPendingSurvivesWriterCrash(t *testing.T) {
	for _, stage := range []string{"created", "before-flush", "during-promotion", "after-promotion"} {
		t.Run(stage, func(t *testing.T) {
			parent, _, trusted, path := registryFixture(t)
			t.Cleanup(func() {
				_ = registry.DeleteKey(parent, boundProvisionPendingKey)
				_ = registry.DeleteKey(parent, boundRotationKey)
			})
			if stage == "after-promotion" || stage == "during-promotion" {
				user, err := windows.GetCurrentProcessToken().GetTokenUser()
				if err != nil {
					t.Fatal(err)
				}
				sid := user.User.Sid.String()
				if err := createBoundProvisionPending(parent, "O:"+sid+"G:"+sid+"D:P(A;;KA;;;"+sid+")", trusted, testBoundState(), flushCredentialKey); err != nil {
					t.Fatal(err)
				}
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(exe, "-test.run=^TestEnrollmentPendingCrashChild$")
			child.Env = append(os.Environ(), "TT_ENROLLMENT_CRASH_PATH="+path, "TT_ENROLLMENT_CRASH_STAGE="+stage)
			if err := child.Run(); err != nil {
				t.Fatalf("child failed: %v", err)
			}
			if ensureNoBoundProvisionPending(parent) == nil {
				t.Fatal("crash left startup unblocked")
			}
			state, err := readBoundProvisionPending(parent, trusted, flushCredentialKey)
			if stage == "created" && err == nil {
				t.Fatal("incomplete marker accepted")
			}
			if stage == "before-flush" && (err != nil || state != testBoundState()) {
				t.Fatal("visible pending record not recovered")
			}
			if (stage == "after-promotion" || stage == "during-promotion") && (err != nil || state != testBoundState()) {
				t.Fatal("pending record lost after promotion crash")
			}
		})
	}
}
