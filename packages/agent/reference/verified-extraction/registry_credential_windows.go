//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Experimental, disconnected journal. A successful RegFlushKey writes the
// registry hive to disk per Microsoft; this does not prove behavior of a
// particular storage stack under power loss, snapshots, rollback, or an
// equally privileged legacy process. Never use it to release quarantine.
var registryOperationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var registryCredentialPattern = regexp.MustCompile(`^ttagent_[a-f0-9]{16}_[a-f0-9]{64}$`)

type registryCredentialRecord struct {
	Version    int    `json:"version"`
	Operation  string `json:"operation"`
	Credential string `json:"credential"`
}

func validRegistryCredential(r registryCredentialRecord) bool {
	return r.Version == 1 && registryOperationPattern.MatchString(r.Operation) && registryCredentialPattern.MatchString(r.Credential)
}

var regCredentialAdvapi = windows.NewLazySystemDLL("advapi32.dll")
var regCredentialCreate = regCredentialAdvapi.NewProc("RegCreateKeyExW")
var regCredentialFlush = regCredentialAdvapi.NewProc("RegFlushKey")

func flushCredentialKey(k registry.Key) error {
	r, _, _ := regCredentialFlush.Call(uintptr(k))
	if r != 0 {
		return fmt.Errorf("registry flush failed")
	}
	return nil
}

// Every effective allow ACE, including read-only ACEs, must be trusted.
// Unknown ACE types are rejected. Parent provenance and old privileged handles
// are outside this primitive and must be established before use.
func validateCredentialRegistryKey(k registry.Key, trusted map[string]bool) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("registry security unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !trusted[owner.String()] {
		return fmt.Errorf("untrusted registry owner")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("registry DACL is not protected")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("registry DACL unavailable")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace == nil {
			return fmt.Errorf("unreadable registry ACE")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return fmt.Errorf("unsupported registry ACE")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !trusted[sid.String()] {
			return fmt.Errorf("untrusted registry access")
		}
	}
	return nil
}

// The caller must hold an already validated, stable parent handle. The fixed
// key name is created exclusively using the REG_CREATED_NEW_KEY disposition.
// A failed/incomplete creation is retained; never replace it automatically.
func prepareRegistryCredential(parent registry.Key, sddl string, trusted map[string]bool, rec registryCredentialRecord) error {
	return prepareRegistryCredentialWithFlush(parent, sddl, trusted, rec, flushCredentialKey)
}

func prepareRegistryCredentialWithFlush(parent registry.Key, sddl string, trusted map[string]bool, rec registryCredentialRecord, flush func(registry.Key) error) error {
	if !validRegistryCredential(rec) {
		return fmt.Errorf("invalid registry candidate")
	}
	if err := validateCredentialRegistryKey(parent, trusted); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("invalid registry security")
	}
	name, _ := windows.UTF16PtrFromString("CredentialRotationPending")
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var h windows.Handle
	var disposition uint32
	r, _, _ := regCredentialCreate.Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, 0, 0, uintptr(registry.QUERY_VALUE|registry.SET_VALUE|windows.READ_CONTROL), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disposition)))
	if r != 0 {
		return fmt.Errorf("registry candidate unavailable")
	}
	k := registry.Key(h)
	defer k.Close()
	if disposition != 1 {
		return fmt.Errorf("registry candidate already exists")
	}
	if err := validateCredentialRegistryKey(k, trusted); err != nil {
		return err
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("registry candidate encoding failed")
	}
	if err := k.SetBinaryValue("Record", b); err != nil {
		return fmt.Errorf("registry candidate write failed")
	}
	return flush(k)
}

// Recovery flushes the hive itself before returning. This matters if a prior
// writer died after setting the value but before its own flush completed.
// The key is never modified by cooperating readers/writers after creation.
func readRegistryCredential(parent registry.Key, trusted map[string]bool) (registryCredentialRecord, error) {
	return readRegistryCredentialWithFlush(parent, trusted, flushCredentialKey)
}

func readRegistryCredentialWithFlush(parent registry.Key, trusted map[string]bool, flush func(registry.Key) error) (registryCredentialRecord, error) {
	var result registryCredentialRecord
	if err := validateCredentialRegistryKey(parent, trusted); err != nil {
		return result, err
	}
	name, _ := windows.UTF16PtrFromString("CredentialRotationPending")
	var h windows.Handle
	if err := windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|windows.READ_CONTROL, &h); err != nil {
		return result, fmt.Errorf("registry candidate unavailable")
	}
	k := registry.Key(h)
	defer k.Close()
	if err := validateCredentialRegistryKey(k, trusted); err != nil {
		return result, err
	}
	linkName, _ := windows.UTF16PtrFromString("SymbolicLinkValue")
	var linkKind, linkSize uint32
	linkErr := windows.RegQueryValueEx(h, linkName, nil, &linkKind, nil, &linkSize)
	if linkErr == nil || linkErr != windows.ERROR_FILE_NOT_FOUND {
		return result, fmt.Errorf("registry links or ambiguous state refused")
	}
	value, _ := windows.UTF16PtrFromString("Record")
	var kind, size uint32
	if windows.RegQueryValueEx(h, value, nil, &kind, nil, &size) != nil || kind != registry.BINARY || size == 0 || size > 512 {
		return result, fmt.Errorf("invalid registry candidate")
	}
	b := make([]byte, size)
	if windows.RegQueryValueEx(h, value, nil, &kind, &b[0], &size) != nil || kind != registry.BINARY || size != uint32(len(b)) {
		return result, fmt.Errorf("registry candidate read failed")
	}
	syntax := json.NewDecoder(bytes.NewReader(b))
	if checkJSONValue(syntax, 0) != nil {
		return result, fmt.Errorf("invalid registry candidate")
	}
	if _, err := syntax.Token(); err != io.EOF {
		return result, fmt.Errorf("invalid registry candidate")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || !validRegistryCredential(result) {
		return registryCredentialRecord{}, fmt.Errorf("invalid registry candidate")
	}
	if err := flush(k); err != nil {
		return registryCredentialRecord{}, err
	}
	return result, nil
}
