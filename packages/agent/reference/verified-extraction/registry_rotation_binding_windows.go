//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Experimental only. The binding is trustworthy only after independent
// authenticated enrollment and a verified TLS request; this store cannot
// establish that provenance, authorize ACK, or fence old privileged work.
const boundRotationKey = "CredentialRotationBoundV3"
const boundProvisionPendingKey = "CredentialRotationProvisionPendingV4"

var boundUUID = regexp.MustCompile(`^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$`)
var boundAgent = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var boundDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var boundDNSLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type rotationBinding struct {
	ID          string `json:"id"`
	AgentID     string `json:"agentId"`
	WorkspaceID string `json:"workspaceId"`
	Origin      string `json:"origin"`
	CAHash      string `json:"caHash"`
}

type boundRotationState struct {
	Version int             `json:"version"`
	Binding rotationBinding `json:"binding"`
	State   rotationState   `json:"state"`
}

func validRotationBinding(b rotationBinding) bool {
	if !boundUUID.MatchString(b.ID) || !boundUUID.MatchString(b.WorkspaceID) || !boundAgent.MatchString(b.AgentID) || !boundDigest.MatchString(b.CAHash) {
		return false
	}
	u, err := url.Parse(b.Origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || strings.HasSuffix(u.Host, ":") || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.ToLower(u.Host) != u.Host || u.Port() == "443" || b.Origin != "https://"+u.Host {
		return false
	}
	host := u.Hostname()
	if host == "" || len(host) > 253 {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		// The experimental Node TLS transport does not support bracketed IPv6
		// hostnames. Refuse it until end-to-end IPv6 handling is qualified.
		if ip.Is6() || ip.String() != host || ip.Zone() != "" || ip.Is4In6() {
			return false
		}
	} else {
		labels := strings.Split(host, ".")
		for _, label := range labels {
			// IDN is deliberately unsupported until its normalization is shared
			// with the Node URL parser and tested against the same vectors.
			if !boundDNSLabel.MatchString(label) || strings.HasPrefix(label, "xn--") {
				return false
			}
		}
		last := labels[len(labels)-1]
		if _, err := strconv.ParseUint(last, 10, 64); err == nil || strings.HasPrefix(last, "0x") {
			return false
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	return true
}

// Serialized V3 CAS. It preserves the complete binding at every transition
// and cannot erase a promoted receipt. It never issues or authorizes ACK.
func lockedTransitionBoundRotation(ctx context.Context, parent registry.Key, trusted map[string]bool, expected, next boundRotationState) error {
	return withRotationLock(ctx, func() error {
		if validateCredentialRegistryKey(parent, trusted) != nil || !validBoundRotationState(expected) || !validBoundRotationState(next) || expected.Binding != next.Binding {
			return fmt.Errorf("invalid bound rotation transition")
		}
		name, _ := windows.UTF16PtrFromString(boundRotationKey)
		var handle windows.Handle
		if windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &handle) != nil {
			return fmt.Errorf("rotation state unavailable")
		}
		k := registry.Key(handle)
		defer k.Close()
		current, err := readBoundRotation(k, trusted, flushCredentialKey)
		if err != nil || current != expected {
			return fmt.Errorf("rotation state changed or unavailable")
		}
		if current == next {
			return nil
		}
		a, b := current.State, next.State
		allowed := a.Phase == "active" && b.Phase == "prepared" && b.Active == a.Active ||
			a.Phase == "prepared" && b.Phase == "committed" && b.Operation == a.Operation && b.Active == a.Active && b.Candidate == a.Candidate ||
			a.Phase == "committed" && b.Phase == "promoted" && b.Operation == a.Operation && b.Active == a.Candidate && b.Candidate == ""
		if !allowed {
			return fmt.Errorf("bound rotation transition rejected")
		}
		return writeBoundRotation(k, next, flushCredentialKey)
	})
}

func validBoundRotationState(b boundRotationState) bool {
	return b.Version == 3 && validRotationBinding(b.Binding) && validRotationState(b.State)
}

// All callers must hold the dedicated mutex. Unknown/old formats are retained
// for explicit reconciliation and never automatically migrated or overwritten.
func initializeBoundRotation(parent registry.Key, sddl string, trusted map[string]bool, initial boundRotationState) error {
	return initializeBoundRotationWithFlush(parent, sddl, trusted, initial, flushCredentialKey)
}

func initializeBoundRotationWithFlush(parent registry.Key, sddl string, trusted map[string]bool, initial boundRotationState, flush func(registry.Key) error) error {
	if !validBoundRotationState(initial) || initial.State.Phase != "active" || validateCredentialRegistryKey(parent, trusted) != nil {
		return fmt.Errorf("invalid bound rotation state")
	}
	for _, name := range []string{"CredentialRotationPending", rotationStateKey} {
		ptr, _ := windows.UTF16PtrFromString(name)
		var existing windows.Handle
		err := windows.RegOpenKeyEx(windows.Handle(parent), ptr, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &existing)
		if err == nil {
			windows.CloseHandle(existing)
			return fmt.Errorf("older rotation state requires reconciliation")
		}
		if err != windows.ERROR_FILE_NOT_FOUND {
			return fmt.Errorf("rotation state unavailable")
		}
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("rotation security invalid")
	}
	name, _ := windows.UTF16PtrFromString(boundRotationKey)
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var handle windows.Handle
	var disposition uint32
	r, _, _ := regCredentialCreate.Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, 0, 0, uintptr(registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&disposition)))
	if r != 0 {
		return fmt.Errorf("rotation state unavailable")
	}
	k := registry.Key(handle)
	defer k.Close()
	if disposition != 1 || validateCredentialRegistryKey(k, trusted) != nil || rejectRegistryLink(k) != nil {
		return fmt.Errorf("rotation state exists or invalid")
	}
	return writeBoundRotation(k, initial, flush)
}

func lockedInitializeBoundRotation(ctx context.Context, parent registry.Key, sddl string, trusted map[string]bool, initial boundRotationState) error {
	return withRotationLock(ctx, func() error { return initializeBoundRotation(parent, sddl, trusted, initial) })
}

func writeBoundRotation(k registry.Key, state boundRotationState, flush func(registry.Key) error) error {
	if !validBoundRotationState(state) {
		return fmt.Errorf("invalid bound rotation state")
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

func readBoundRotation(k registry.Key, trusted map[string]bool, flush func(registry.Key) error) (boundRotationState, error) {
	var result boundRotationState
	if validateCredentialRegistryKey(k, trusted) != nil || rejectRegistryLink(k) != nil {
		return result, fmt.Errorf("rotation state security invalid")
	}
	name, _ := windows.UTF16PtrFromString("Record")
	var kind, size uint32
	if windows.RegQueryValueEx(windows.Handle(k), name, nil, &kind, nil, &size) != nil || kind != registry.BINARY || size == 0 || size > 2048 {
		return result, fmt.Errorf("rotation state unavailable")
	}
	b := make([]byte, size)
	defer clear(b)
	if windows.RegQueryValueEx(windows.Handle(k), name, nil, &kind, &b[0], &size) != nil || kind != registry.BINARY || size != uint32(len(b)) {
		return result, fmt.Errorf("rotation state unavailable")
	}
	syntax := json.NewDecoder(bytes.NewReader(b))
	if checkJSONValue(syntax, 0) != nil {
		return result, fmt.Errorf("invalid rotation state")
	}
	if _, err := syntax.Token(); err != io.EOF {
		return result, fmt.Errorf("invalid rotation state")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || !validBoundRotationState(result) {
		return boundRotationState{}, fmt.Errorf("invalid rotation state")
	}
	if flush(k) != nil {
		return boundRotationState{}, fmt.Errorf("rotation flush failed")
	}
	return result, nil
}

// Read-only startup check: a mismatch or non-active phase returns no bearer.
// expected must be computed from the actual verified endpoint and CA bytes,
// never from the same unverified journal being read.
func boundStartupCredential(ctx context.Context, parent registry.Key, trusted map[string]bool, expected rotationBinding) (string, error) {
	if !validRotationBinding(expected) {
		return "", fmt.Errorf("rotation binding unavailable")
	}
	var credential string
	err := withRotationLock(ctx, func() error {
		if validateCredentialRegistryKey(parent, trusted) != nil {
			return fmt.Errorf("rotation parent invalid")
		}
		if ensureNoBoundProvisionPending(parent) != nil {
			return fmt.Errorf("provisioning requires reconciliation")
		}
		name, _ := windows.UTF16PtrFromString(boundRotationKey)
		var handle windows.Handle
		if windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &handle) != nil {
			return fmt.Errorf("rotation state unavailable")
		}
		k := registry.Key(handle)
		defer k.Close()
		state, err := readBoundRotation(k, trusted, flushCredentialKey)
		if err != nil || state.Binding != expected || state.State.Phase != "active" {
			return fmt.Errorf("rotation binding mismatch or reconciliation required")
		}
		credential = state.State.Active
		return nil
	})
	if err != nil {
		return "", err
	}
	return credential, nil
}

func ensureNoBoundProvisionPending(parent registry.Key) error {
	name, _ := windows.UTF16PtrFromString(boundProvisionPendingKey)
	var h windows.Handle
	err := windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &h)
	if err == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("provisioning requires reconciliation")
	}
	if err != windows.ERROR_FILE_NOT_FOUND {
		return fmt.Errorf("provisioning state unavailable")
	}
	return nil
}
