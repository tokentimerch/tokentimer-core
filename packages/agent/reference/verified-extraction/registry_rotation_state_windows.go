//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Experimental only: callers must not issue an ACK based on this state.
// The mutex serializes cooperating processes, not old or privileged writers.
const rotationStateKey = "CredentialRotationStateV2"
const rotationMutexName = `Global\TokenTimer.Agent.CredentialRotation.v2`

type rotationState struct {
	Version   int    `json:"version"`
	Phase     string `json:"phase"`
	Operation string `json:"operation"`
	Active    string `json:"active"`
	Candidate string `json:"candidate"`
}

func validRotationState(s rotationState) bool {
	if s.Version != 2 || !registryCredentialPattern.MatchString(s.Active) {
		return false
	}
	switch s.Phase {
	case "active":
		return s.Operation == "" && s.Candidate == ""
	case "promoted":
		return registryOperationPattern.MatchString(s.Operation) && s.Candidate == ""
	case "prepared", "committed":
		return registryOperationPattern.MatchString(s.Operation) && registryCredentialPattern.MatchString(s.Candidate) && s.Active != s.Candidate
	default:
		return false
	}
}

func withRotationLock(ctx context.Context, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return fmt.Errorf("rotation lock unavailable")
	}
	name, _ := windows.UTF16PtrFromString(rotationMutexName)
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateMutex(&attrs, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return fmt.Errorf("rotation lock unavailable")
	}
	if h == 0 {
		return fmt.Errorf("rotation lock unavailable")
	}
	defer windows.CloseHandle(h)
	if validateInstallMutex(h) != nil {
		return fmt.Errorf("rotation lock security invalid")
	}
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("rotation lock unavailable")
		}
		state, err := windows.WaitForSingleObject(h, 100)
		if err != nil {
			return fmt.Errorf("rotation lock unavailable")
		}
		if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
			defer windows.ReleaseMutex(h)
			if ctx.Err() != nil {
				return fmt.Errorf("rotation lock unavailable")
			}
			// Abandonment says nothing about previously launched network or SCM
			// effects. Each local operation must validate and flush its own state.
			return fn()
		}
		if state != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("rotation lock unavailable")
		}
		time.Sleep(time.Millisecond)
	}
}

// Caller holds the rotation lock and an already validated parent lease.
// Creating V2 refuses any legacy candidate, including incomplete or linked keys.
func initializeRotationState(parent registry.Key, sddl string, trusted map[string]bool, active string) error {
	if !validRotationState(rotationState{Version: 2, Phase: "active", Active: active}) {
		return fmt.Errorf("invalid rotation state")
	}
	if validateCredentialRegistryKey(parent, trusted) != nil {
		return fmt.Errorf("rotation parent invalid")
	}
	legacy, _ := windows.UTF16PtrFromString("CredentialRotationPending")
	var old windows.Handle
	err := windows.RegOpenKeyEx(windows.Handle(parent), legacy, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &old)
	if err == nil {
		windows.CloseHandle(old)
		return fmt.Errorf("legacy rotation state requires reconciliation")
	}
	if err != windows.ERROR_FILE_NOT_FOUND {
		return fmt.Errorf("legacy rotation state unavailable")
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("rotation security invalid")
	}
	name, _ := windows.UTF16PtrFromString(rotationStateKey)
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var h windows.Handle
	var disposition uint32
	r, _, _ := regCredentialCreate.Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, 0, 0, uintptr(registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disposition)))
	if r != 0 {
		return fmt.Errorf("rotation state unavailable")
	}
	k := registry.Key(h)
	defer k.Close()
	if disposition != 1 || validateCredentialRegistryKey(k, trusted) != nil || rejectRegistryLink(k) != nil {
		return fmt.Errorf("rotation state already exists or invalid")
	}
	return writeRotationState(k, rotationState{Version: 2, Phase: "active", Active: active}, flushCredentialKey)
}

func writeRotationState(k registry.Key, state rotationState, flush func(registry.Key) error) error {
	if !validRotationState(state) {
		return fmt.Errorf("invalid rotation state")
	}
	b, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("rotation encoding failed")
	}
	defer clear(b)
	if k.SetBinaryValue("Record", b) != nil {
		return fmt.Errorf("rotation write failed")
	}
	if flush(k) != nil {
		return fmt.Errorf("rotation flush failed")
	}
	return nil
}

func readRotationState(k registry.Key, flush func(registry.Key) error) (rotationState, error) {
	var state rotationState
	name, _ := windows.UTF16PtrFromString("Record")
	var kind, size uint32
	if windows.RegQueryValueEx(windows.Handle(k), name, nil, &kind, nil, &size) != nil || kind != registry.BINARY || size == 0 || size > 1024 {
		return state, fmt.Errorf("rotation state unavailable")
	}
	b := make([]byte, size)
	if windows.RegQueryValueEx(windows.Handle(k), name, nil, &kind, &b[0], &size) != nil || kind != registry.BINARY || size != uint32(len(b)) {
		clear(b)
		return state, fmt.Errorf("rotation state unavailable")
	}
	defer clear(b)
	syntax := json.NewDecoder(bytes.NewReader(b))
	if checkJSONValue(syntax, 0) != nil {
		return state, fmt.Errorf("invalid rotation state")
	}
	if _, err := syntax.Token(); err != io.EOF {
		return state, fmt.Errorf("invalid rotation state")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&state) != nil || !validRotationState(state) {
		return rotationState{}, fmt.Errorf("invalid rotation state")
	}
	if flush(k) != nil {
		return rotationState{}, fmt.Errorf("rotation flush failed")
	}
	return state, nil
}

func lockedRotationInitialize(ctx context.Context, parent registry.Key, sddl string, trusted map[string]bool, active string) error {
	return withRotationLock(ctx, func() error { return initializeRotationState(parent, sddl, trusted, active) })
}

func lockedRotationRead(ctx context.Context, parent registry.Key, trusted map[string]bool) (rotationState, error) {
	var state rotationState
	err := withRotationLock(ctx, func() error {
		if validateCredentialRegistryKey(parent, trusted) != nil {
			return fmt.Errorf("rotation parent invalid")
		}
		name, _ := windows.UTF16PtrFromString(rotationStateKey)
		var h windows.Handle
		if windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &h) != nil {
			return fmt.Errorf("rotation state unavailable")
		}
		k := registry.Key(h)
		defer k.Close()
		if validateCredentialRegistryKey(k, trusted) != nil || rejectRegistryLink(k) != nil {
			return fmt.Errorf("rotation state security invalid")
		}
		var err error
		state, err = readRotationState(k, flushCredentialKey)
		return err
	})
	if err != nil {
		return rotationState{}, err
	}
	return state, nil
}

// lockedRotationTransition keeps the mutex for the full open, compare, write
// and flush. It is deliberately not wired to a running agent.
func lockedRotationTransition(ctx context.Context, parent registry.Key, trusted map[string]bool, expected, next rotationState) error {
	return withRotationLock(ctx, func() error {
		if validateCredentialRegistryKey(parent, trusted) != nil {
			return fmt.Errorf("rotation parent invalid")
		}
		name, _ := windows.UTF16PtrFromString(rotationStateKey)
		var h windows.Handle
		if windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &h) != nil {
			return fmt.Errorf("rotation state unavailable")
		}
		k := registry.Key(h)
		defer k.Close()
		return transitionRotationState(k, trusted, expected, next, flushCredentialKey)
	})
}

// compare-and-swap requires the complete previous record, including operation
// and credentials. No transition authorizes remote acknowledgement.
func transitionRotationState(k registry.Key, trusted map[string]bool, expected, next rotationState, flush func(registry.Key) error) error {
	if validateCredentialRegistryKey(k, trusted) != nil || rejectRegistryLink(k) != nil {
		return fmt.Errorf("rotation state security invalid")
	}
	current, err := readRotationState(k, flush)
	if err != nil || current != expected {
		return fmt.Errorf("rotation state changed or unavailable")
	}
	if current == next {
		return nil
	}
	allowed := current.Phase == "active" && next.Phase == "prepared" && next.Active == current.Active ||
		current.Phase == "prepared" && next.Phase == "committed" && next.Operation == current.Operation && next.Active == current.Active && next.Candidate == current.Candidate ||
		current.Phase == "committed" && next.Phase == "promoted" && next.Active == current.Candidate && next.Operation == current.Operation && next.Candidate == ""
	if !allowed || !validRotationState(next) {
		return fmt.Errorf("rotation transition rejected")
	}
	return writeRotationState(k, next, flush)
}
