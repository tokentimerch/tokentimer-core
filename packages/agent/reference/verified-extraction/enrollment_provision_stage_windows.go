//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"context"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Staging is never executable. The pending key is deliberately retained even
// after promotion, so crashes or failed flushes cannot silently authorize
// startup. No cleanup or ACK operation is implemented.
func createBoundProvisionPending(parent registry.Key, sddl string, trusted map[string]bool, state boundRotationState, flush func(registry.Key) error) error {
	return createBoundProvisionPendingWithHook(parent, sddl, trusted, state, flush, nil)
}

func createBoundProvisionPendingWithHook(parent registry.Key, sddl string, trusted map[string]bool, state boundRotationState, flush func(registry.Key) error, afterCreate func() error) error {
	if !validBoundRotationState(state) || state.State.Phase != "active" || validateCredentialRegistryKey(parent, trusted) != nil {
		return fmt.Errorf("provisioning unavailable")
	}
	for _, key := range []string{"CredentialRotationPending", rotationStateKey, boundRotationKey} {
		name, _ := windows.UTF16PtrFromString(key)
		var h windows.Handle
		err := windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &h)
		if err == nil {
			windows.CloseHandle(h)
			return fmt.Errorf("existing state requires reconciliation")
		}
		if err != windows.ERROR_FILE_NOT_FOUND {
			return fmt.Errorf("provisioning unavailable")
		}
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("provisioning unavailable")
	}
	name, _ := windows.UTF16PtrFromString(boundProvisionPendingKey)
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var h windows.Handle
	var disposition uint32
	r, _, _ := regCredentialCreate.Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, 0, 0, uintptr(registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disposition)))
	if r != 0 {
		return fmt.Errorf("provisioning unavailable")
	}
	k := registry.Key(h)
	defer k.Close()
	if disposition != 1 || validateCredentialRegistryKey(k, trusted) != nil || rejectRegistryLink(k) != nil {
		return fmt.Errorf("provisioning unavailable")
	}
	if afterCreate != nil && afterCreate() != nil {
		return fmt.Errorf("provisioning unavailable")
	}
	return writeBoundRotation(k, state, flush)
}

func readBoundProvisionPending(parent registry.Key, trusted map[string]bool, flush func(registry.Key) error) (boundRotationState, error) {
	var empty boundRotationState
	if validateCredentialRegistryKey(parent, trusted) != nil {
		return empty, fmt.Errorf("provisioning unavailable")
	}
	name, _ := windows.UTF16PtrFromString(boundProvisionPendingKey)
	var h windows.Handle
	if windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &h) != nil {
		return empty, fmt.Errorf("provisioning unavailable")
	}
	k := registry.Key(h)
	defer k.Close()
	return readBoundRotation(k, trusted, flush)
}

// Explicit recovery repeats TLS identity verification, flushes and rereads the
// pending record under the mutex, and writes V3. It keeps the pending marker:
// no startup or ACK is authorized, even when the final flush reports success.
func promoteBoundProvision(ctx context.Context, parent registry.Key, sddl string, trusted map[string]bool, origin string, ca []byte, credential, agentID, workspaceID string) error {
	return withRotationLock(ctx, func() error {
		pending, err := readBoundProvisionPending(parent, trusted, flushCredentialKey)
		if err != nil {
			return fmt.Errorf("provisioning unavailable")
		}
		binding, err := verifyEnrollmentIdentity(ctx, origin, ca, credential, agentID, workspaceID)
		if err != nil || ctx.Err() != nil || pending.Binding != binding || pending.State.Phase != "active" || pending.State.Active != credential {
			return fmt.Errorf("provisioning unavailable")
		}
		name, _ := windows.UTF16PtrFromString(boundRotationKey)
		var handle windows.Handle
		openErr := windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &handle)
		if openErr == nil {
			key := registry.Key(handle)
			defer key.Close()
			current, err := readBoundRotation(key, trusted, flushCredentialKey)
			if err != nil || current != pending {
				return fmt.Errorf("provisioning unavailable")
			}
			return nil
		}
		if openErr != windows.ERROR_FILE_NOT_FOUND {
			return fmt.Errorf("provisioning unavailable")
		}
		if initializeBoundRotation(parent, sddl, trusted, pending) != nil {
			return fmt.Errorf("provisioning unavailable")
		}
		return nil
	})
}

// Recovery confirms the current local records and server identity without
// clearing the pending marker, returning a bearer, or authorizing execution.
// An API response may become stale after return; old SYSTEM actors are outside
// the mutex boundary. All callers must remain fail-closed without an external
// provenance and quiescence guarantee.
func inspectBoundProvisionRecovery(ctx context.Context, parent registry.Key, trusted map[string]bool, origin string, ca []byte, credential, agentID, workspaceID string) (rotationBinding, error) {
	var result rotationBinding
	err := withRotationLock(ctx, func() error {
		pending, err := readBoundProvisionPending(parent, trusted, flushCredentialKey)
		if err != nil {
			return fmt.Errorf("provisioning unavailable")
		}
		name, _ := windows.UTF16PtrFromString(boundRotationKey)
		var h windows.Handle
		if windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &h) != nil {
			return fmt.Errorf("provisioning unavailable")
		}
		key := registry.Key(h)
		defer key.Close()
		active, err := readBoundRotation(key, trusted, flushCredentialKey)
		if err != nil || active != pending || pending.State.Phase != "active" || pending.State.Active != credential {
			return fmt.Errorf("provisioning unavailable")
		}
		binding, err := verifyEnrollmentIdentity(ctx, origin, ca, credential, agentID, workspaceID)
		if err != nil || ctx.Err() != nil || binding != pending.Binding {
			return fmt.Errorf("provisioning unavailable")
		}
		result = binding
		return nil
	})
	if err != nil {
		return rotationBinding{}, err
	}
	return result, nil
}
