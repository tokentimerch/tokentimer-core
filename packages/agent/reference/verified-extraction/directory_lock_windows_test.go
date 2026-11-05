//go:build windows

package verifiedextraction

import (
	"golang.org/x/sys/windows"
	"os"
	"strings"
	"testing"
)

func TestQuarantineDirectoryHandlePreventsReplacement(t *testing.T) {
	for _, target := range []string{"parent", "stage"} {
		t.Run(target, func(t *testing.T) {
			f := newReleaseFixture(t, strings.Repeat("f", 32))
			path := f.parent
			policy := f.parentPolicy
			if target == "stage" {
				path = f.stages[0]
				policy = f.stagePolicy
			}
			h, err := lockQuarantineDirectory(path, policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+"-replaced"); err == nil {
				windows.CloseHandle(h)
				t.Fatal("directory renamed while locked")
			}
			if err := windows.CloseHandle(h); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+"-replaced"); err != nil {
				t.Fatalf("directory remained locked after release: %v", err)
			}
		})
	}
}
