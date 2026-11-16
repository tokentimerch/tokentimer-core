//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	verified "tokentimer-verified-extraction"
)

type fakeStage struct {
	root                string
	lockErr, cleanupErr error
	locked, cleaned     bool
}

func (s *fakeStage) Root() string       { return s.root }
func (s *fakeStage) LockPayload() error { s.locked = true; return s.lockErr }
func (s *fakeStage) Cleanup() error     { s.cleaned = true; return s.cleanupErr }
func (s *fakeStage) Close()             {}

func TestReceiptRequiresLockVerificationAndCleanup(t *testing.T) {
	for _, failure := range []string{"lock", "verify", "cleanup", "none"} {
		t.Run(failure, func(t *testing.T) {
			s := &fakeStage{root: t.TempDir()}
			if failure == "lock" {
				s.lockErr = errors.New("refused")
			}
			if failure == "cleanup" {
				s.cleanupErr = errors.New("uncertain")
			}
			called := false
			r, err := runWithStage([]byte("fixture"), "candidate", "amd64", s, func(path string) error {
				called = true
				if !s.locked || path != filepath.Join(s.root, "node.exe") {
					t.Fatal("verification ran without lock")
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatal(err)
				}
				if failure == "verify" {
					return errors.New("untrusted")
				}
				return nil
			})
			if !s.cleaned {
				t.Fatal("cleanup not attempted")
			}
			if failure == "none" {
				if err != nil || r.Kind == "" || r.RuntimeExecuted || r.InstallationPerformed {
					t.Fatalf("unexpected receipt: %+v %v", r, err)
				}
			} else if err == nil || r != (receipt{}) {
				t.Fatalf("%s failure produced a receipt", failure)
			}
			if failure == "lock" && called {
				t.Fatal("verification after lock failure")
			}
		})
	}
}

func TestUnprivilegedHostRefusesProtectedStaging(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires non-elevated token")
	}
	stage, err := verified.NewPrivateStaging()
	if err == nil {
		stage.Close()
		t.Fatal("unprivileged protected staging accepted")
	}
}
