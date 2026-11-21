//go:build windows

package verifiedextraction

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitCanceledChildReportsFailureBeforeWaiting(t *testing.T) {
	done := make(chan error, 1)
	reported := make(chan struct{}, 1)
	result := make(chan error, 1)
	failure := errors.New("termination failure")
	go func() {
		result <- waitCanceledChild(context.Canceled, done, func() error { return failure }, func() { reported <- struct{}{} })
	}()
	select {
	case <-reported:
	case <-time.After(5 * time.Second):
		t.Fatal("termination failure was not reported while the child is running")
	}
	select {
	case err := <-result:
		t.Fatalf("returned before the child exited: %v", err)
	default:
	}
	done <- nil
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, failure) {
			t.Fatalf("lost cancellation or termination failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not return after child exit")
	}
}

func TestWaitCanceledChildDoesNotReportSuccessfulTermination(t *testing.T) {
	done := make(chan error, 1)
	done <- nil
	err := waitCanceledChild(context.Canceled, done, func() error { return nil }, func() { t.Error("reported a successful termination") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
}
