//go:build windows

package verifiedextraction

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeRestart struct {
	calls []string
	fail  string
}

func (f *fakeRestart) step(s string) error {
	f.calls = append(f.calls, s)
	if f.fail == s {
		return errors.New("failure")
	}
	return nil
}
func (f *fakeRestart) VerifyBefore(context.Context) error { return f.step("verify-before") }
func (f *fakeRestart) RequestStop(context.Context) error  { return f.step("stop-requested") }
func (f *fakeRestart) WaitStoppedAndOldProcessesExited(context.Context) error {
	return f.step("verify-stopped")
}
func (f *fakeRestart) RequestStart(context.Context) error  { return f.step("start-requested") }
func (f *fakeRestart) VerifyStarted(context.Context) error { return f.step("verify-started") }

type fakeRestartJournal struct {
	steps []string
	fail  string
}

func (j *fakeRestartJournal) CanRestart() bool { return true }
func (j *fakeRestartJournal) FlushStep(s string) error {
	j.steps = append(j.steps, s)
	if j.fail == s {
		return errors.New("failure")
	}
	return nil
}
func TestRestartProtocolFlushesBeforeEveryActionAndFailsClosed(t *testing.T) {
	names := []string{"verify-before", "stop-requested", "verify-stopped", "start-requested", "verify-started"}
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			for _, failure := range []string{"journal", "service"} {
				t.Run(failure, func(t *testing.T) {
					c := &fakeRestart{}
					j := &fakeRestartJournal{}
					if failure == "journal" {
						j.fail = name
					} else {
						c.fail = name
					}
					if err := restartUnderVerifiedLock(context.Background(), c, j); err == nil {
						t.Fatal("failure accepted")
					}
					want := i
					if failure == "service" {
						want++
					}
					if !reflect.DeepEqual(c.calls, names[:want]) && !(want == 0 && len(c.calls) == 0) {
						t.Fatalf("unexpected actions: %v", c.calls)
					}
					if !reflect.DeepEqual(j.steps, names[:i+1]) {
						t.Fatalf("unexpected checkpoints: %v", j.steps)
					}
				})
			}
		})
	}
	c := &fakeRestart{}
	j := &fakeRestartJournal{}
	if err := restartUnderVerifiedLock(context.Background(), c, j); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.calls, names) || len(j.steps) != len(names)+1 || j.steps[len(j.steps)-1] != "verified" {
		t.Fatal("incomplete protocol")
	}
}
func TestStopOnlyNeverStartsServiceAndFailsClosed(t *testing.T) {
	for _, fail := range []string{"", "verify-before", "stop-requested", "verify-stopped"} {
		t.Run("failure-"+fail, func(t *testing.T) {
			c := &fakeRestart{fail: fail}
			j := &fakeRestartJournal{}
			err := stopUnderVerifiedLock(context.Background(), c, j)
			if (err == nil) != (fail == "") {
				t.Fatalf("unexpected stop result: %v", err)
			}
			for _, call := range c.calls {
				if call == "start-requested" || call == "verify-started" {
					t.Fatal("stop-only path tried to start service")
				}
			}
			if fail == "" && (len(j.steps) != 4 || j.steps[3] != "stopped-verified") {
				t.Fatal("missing stopped checkpoint")
			}
		})
	}
}

type fakeDisableStop struct{ fakeRestart }

func (f *fakeDisableStop) RequestDisable(context.Context) error { return f.step("disable-requested") }
func (f *fakeDisableStop) VerifyDisabled(context.Context) error { return f.step("verify-disabled") }
func TestDisableStopProtocolFlushesBeforeEveryAction(t *testing.T) {
	names := []string{"verify-before", "disable-requested", "verify-disabled", "stop-requested", "verify-stopped"}
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{"journal", "service"} {
				t.Run(kind, func(t *testing.T) {
					c := &fakeDisableStop{}
					j := &fakeRestartJournal{}
					if kind == "journal" {
						j.fail = name
					} else {
						c.fail = name
					}
					if err := disableAndStopUnderVerifiedLock(context.Background(), c, j); err == nil {
						t.Fatal("failure accepted")
					}
					want := i
					if kind == "service" {
						want++
					}
					if !reflect.DeepEqual(c.calls, names[:want]) && !(want == 0 && len(c.calls) == 0) {
						t.Fatalf("unexpected actions: %v", c.calls)
					}
					if !reflect.DeepEqual(j.steps, names[:i+1]) {
						t.Fatalf("unexpected checkpoints: %v", j.steps)
					}
				})
			}
		})
	}
	c := &fakeDisableStop{}
	j := &fakeRestartJournal{}
	if err := disableAndStopUnderVerifiedLock(context.Background(), c, j); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.calls, names) || len(j.steps) != 6 || j.steps[5] != "stopped-verified" {
		t.Fatal("incomplete sequence")
	}
}
