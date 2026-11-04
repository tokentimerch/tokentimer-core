//go:build windows

package verifiedextraction

import (
	"context"
	"fmt"
	"time"
)

// restartController is deliberately private: implementations must authenticate
// SCM account, configuration and the newly-created processes under retained
// inventory locks. A Running status alone cannot implement VerifyStarted.
type restartController interface {
	VerifyBefore(context.Context) error
	RequestStop(context.Context) error
	WaitStoppedAndOldProcessesExited(context.Context) error
	RequestStart(context.Context) error
	VerifyStarted(context.Context) error
}

type restartStepWriter interface {
	FlushStep(string) error
	CanRestart() bool
}

// restartUnderVerifiedLock is a protocol component, not proof of isolation.
// A caller must hold authenticated application and journal locks throughout,
// retain the recovery barrier on failure, and independently review persistent
// actors. A retry is permitted only before a prior stop request; later interruption
// requires manual review because process handles are no longer available.
func restartUnderVerifiedLock(ctx context.Context, c restartController, journal restartStepWriter) error {
	if c == nil || journal == nil || !journal.CanRestart() {
		return fmt.Errorf("restart prerequisites unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"verify-before", c.VerifyBefore},
		{"stop-requested", c.RequestStop},
		{"verify-stopped", c.WaitStoppedAndOldProcessesExited},
		{"start-requested", c.RequestStart},
		{"verify-started", c.VerifyStarted},
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := journal.FlushStep(step.name); err != nil {
			return fmt.Errorf("restart checkpoint failed")
		}
		if err := step.run(ctx); err != nil {
			return fmt.Errorf("restart step %s failed", step.name)
		}
	}
	if err := journal.FlushStep("verified"); err != nil {
		return fmt.Errorf("restart checkpoint failed")
	}
	return nil
}
