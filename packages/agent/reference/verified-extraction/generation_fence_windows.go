//go:build windows && generationfenceexperiment

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

// generationLease is an experimental, inactive primitive for cooperating
// executors. It pins one protected marker while a caller performs an operation.
// It does not fence SCM, WMI, an already queued command, or a legacy executor.
// It must never be used as permission to release an existing quarantine.
type generationLease struct {
	marker, directory windows.Handle
	ancestors         *bootstraplock.Locks
	once              sync.Once
}

func (l *generationLease) Close() {
	l.once.Do(func() { windows.CloseHandle(l.marker); windows.CloseHandle(l.directory); l.ancestors.Close() })
}

type generationRecord struct {
	Version    int    `json:"version"`
	Generation string `json:"generation"`
}

// lockGeneration pins an existing marker; creation, authenticated generation
// selection, anti-rollback and coordination with the server are intentionally
// outside this primitive. A cooperating caller must hold the lease through its
// entire local operation, but Windows/SCM do not enforce this convention.
func lockGeneration(dir, expected string, parentPolicy, statePolicy bootstraplock.Policy) (_ *generationLease, err error) {
	if !filepath.IsAbs(dir) || !digest.MatchString(expected) {
		return nil, fmt.Errorf("invalid generation request")
	}
	ancestors, err := bootstraplock.LockAncestors(dir, parentPolicy)
	if err != nil {
		return nil, fmt.Errorf("generation ancestors unavailable")
	}
	defer func() {
		if err != nil {
			ancestors.Close()
		}
	}()
	directory, err := lockQuarantineDirectory(dir, statePolicy)
	if err != nil {
		return nil, fmt.Errorf("generation directory unavailable")
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(directory)
		}
	}()
	path, err := windows.UTF16PtrFromString(filepath.Join(dir, "generation-fence.json"))
	if err != nil {
		return nil, fmt.Errorf("invalid generation path")
	}
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("generation marker unavailable")
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(h)
		}
	}()
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 512 {
		return nil, fmt.Errorf("invalid generation marker identity")
	}
	if aclErr := validateIntentACL(h, &PrivateStaging{policy: statePolicy}); aclErr != nil {
		return nil, fmt.Errorf("untrusted generation marker ACL: %w", aclErr)
	}
	b := make([]byte, info.FileSizeLow)
	var n uint32
	if windows.ReadFile(h, b, &n, nil) != nil || n != uint32(len(b)) {
		return nil, fmt.Errorf("generation marker read failed")
	}
	syntax := json.NewDecoder(bytes.NewReader(b))
	if checkJSONValue(syntax, 0) != nil {
		return nil, fmt.Errorf("invalid generation marker JSON")
	}
	if _, e := syntax.Token(); e != io.EOF {
		return nil, fmt.Errorf("invalid generation marker JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	var record generationRecord
	if decoder.Decode(&record) != nil || record.Version != 1 || !digest.MatchString(record.Generation) || record.Generation != expected {
		return nil, fmt.Errorf("generation mismatch")
	}
	return &generationLease{marker: h, directory: directory, ancestors: ancestors}, nil
}

// withGenerationGuard holds a caller-provided shared exclusion lock across
// marker validation and the entire operation. The lock must be the same one
// held by every cooperating writer rotating the marker; this prototype does not
// authenticate that policy and must not be used to approve legacy recovery.
func withGenerationGuard(ctx context.Context, dir, expected string, parentPolicy, statePolicy bootstraplock.Policy, acquire func(context.Context) (func() error, error), operation func() error) (err error) {
	if acquire == nil || operation == nil {
		return fmt.Errorf("generation guard dependencies unavailable")
	}
	release, err := acquire(ctx)
	if err != nil {
		return err
	}
	if release == nil {
		return fmt.Errorf("generation guard lock unavailable")
	}
	defer func() {
		if e := release(); e != nil {
			err = fmt.Errorf("generation guard release failed: %w", e)
		}
	}()
	lease, err := lockGeneration(dir, expected, parentPolicy, statePolicy)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

// withDirtyGenerationEffect is a prototype for local, cooperating actors.
// The caller must hold withGenerationGuard's mutex and lease throughout. A
// flushed marker precedes the effect and is deleted only after settled reports
// success. settled must include any durable local and remote side effects;
// process exit or network timeout alone is not sufficient evidence. Marker
// absence is never proof that a legacy or noncooperating actor has stopped.
func withDirtyGenerationEffect(dir, sddl string, policy bootstraplock.Policy, effect, settled func() error) (err error) {
	if effect == nil || settled == nil {
		return fmt.Errorf("dirty effect dependencies unavailable")
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("invalid dirty marker ACL")
	}
	name, err := windows.UTF16PtrFromString(filepath.Join(dir, "generation-dirty.intent"))
	if err != nil {
		return fmt.Errorf("invalid dirty marker path")
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, &attrs, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return fmt.Errorf("dirty intent already exists or cannot be created")
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || validateIntentACL(h, &PrivateStaging{policy: policy}) != nil {
		return fmt.Errorf("dirty intent rejected; retain for reconciliation")
	}
	b := []byte("generation-effect-intent-v1\n")
	var n uint32
	if windows.WriteFile(h, b, &n, nil) != nil || int(n) != len(b) || windows.FlushFileBuffers(h) != nil {
		return fmt.Errorf("dirty intent persistence failed; retain for reconciliation")
	}
	if err := effect(); err != nil {
		return fmt.Errorf("generation effect requires reconciliation: %w", err)
	}
	if err := settled(); err != nil {
		return fmt.Errorf("generation effect not settled: %w", err)
	}
	disposition := byte(1)
	if err := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &disposition, 1); err != nil {
		return fmt.Errorf("dirty intent retained: %w", err)
	}
	return nil
}

// withCooperativeDirtyEffect composes both experimental gates in their required
// order. It is deliberately not connected to installation or service startup.
func withCooperativeDirtyEffect(ctx context.Context, dir, generation, sddl string, parentPolicy, statePolicy bootstraplock.Policy, acquire func(context.Context) (func() error, error), effect, settled func() error) error {
	return withGenerationGuard(ctx, dir, generation, parentPolicy, statePolicy, acquire, func() error { return withDirtyGenerationEffect(dir, sddl, statePolicy, effect, settled) })
}
