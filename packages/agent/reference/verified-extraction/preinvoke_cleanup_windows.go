//go:build windows

package verifiedextraction

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// abortBeforeInvocation is only valid on the two fresh, flushed stages in the
// process that created them, while the install mutex is still held and before
// any installer invocation. A crash at any point leaves a marker until both
// directories have gone; a partially removed pair remains fail-closed.
func abortBeforeInvocation(payload, scratch *PrivateStaging, expected ExecutionIntent) error {
	return abortBeforeInvocationWith(payload, scratch, expected, func(s *PrivateStaging) error { return s.cleanupLocked(true) }, func(h windows.Handle) error {
		b := byte(1)
		return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &b, 1)
	})
}

func abortBeforeInvocationWith(payload, scratch *PrivateStaging, expected ExecutionIntent, removeStage func(*PrivateStaging) error, removeMarker func(windows.Handle) error) error {
	if payload == nil || scratch == nil || payload == scratch {
		return fmt.Errorf("invalid pre-invocation stages")
	}
	first, second := payload, scratch
	if strings.ToLower(first.path) > strings.ToLower(second.path) {
		first, second = second, first
	}
	first.intentMu.Lock()
	defer first.intentMu.Unlock()
	second.intentMu.Lock()
	defer second.intentMu.Unlock()
	stages := []*PrivateStaging{payload, scratch}
	handles := make([]windows.Handle, 0, 2)
	defer func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}()
	for _, s := range stages {
		if !s.freshOwned || !s.intentFlushed || s.ancestors == nil || s.staging == nil || s.payload == nil {
			return fmt.Errorf("stage is not a fresh flushed intent")
		}
		path, err := windows.UTF16PtrFromString(s.path + ".intent")
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return fmt.Errorf("lock protected intent: %w", err)
		}
		handles = append(handles, h)
		got, err := inspectQuarantineHandle(s, h)
		if err != nil || got.Transaction != expected.Transaction || got.ArchiveSHA256 != expected.ArchiveSHA256 || got.PreviousSCMSHA256 != expected.PreviousSCMSHA256 || subtle.ConstantTimeCompare([]byte(got.Secret), []byte(expected.Secret)) != 1 {
			return fmt.Errorf("protected intent mismatch")
		}
	}
	if payload.identity == scratch.identity {
		return fmt.Errorf("staging identities collide")
	}
	for _, s := range stages {
		if err := removeStage(s); err != nil {
			return fmt.Errorf("pre-invocation cleanup retained intents: %w", err)
		}
	}
	for _, h := range handles {
		if err := removeMarker(h); err != nil {
			return fmt.Errorf("pre-invocation intent retained: %w", err)
		}
	}
	return nil
}
