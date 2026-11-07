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

// registryParentLease holds each verified key open for the lifetime of the
// journal operation. A production caller must use a fixed, installer-owned
// path; this experimental helper does not establish installation provenance.
type registryParentLease struct{ handles []registry.Key }

func (l *registryParentLease) Close() {
	for i := len(l.handles) - 1; i >= 0; i-- {
		_ = l.handles[i].Close()
	}
	l.handles = nil
}

func rejectRegistryLink(k registry.Key) error {
	linkName, _ := windows.UTF16PtrFromString("SymbolicLinkValue")
	var kind, size uint32
	err := windows.RegQueryValueEx(windows.Handle(k), linkName, nil, &kind, nil, &size)
	if err == nil || err != windows.ERROR_FILE_NOT_FOUND {
		return fmt.Errorf("registry link or ambiguous state refused")
	}
	return nil
}

// Registry ancestors may be readable by ordinary users, but none may be
// writable, replaceable or owned by them. Refuse unrecognized ACE types.
func validateRegistryAncestor(k registry.Key, trusted map[string]bool) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("registry ancestor security unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !trusted[owner.String()] {
		return fmt.Errorf("untrusted registry ancestor owner")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("registry ancestor DACL unavailable")
	}
	const writeMask uint32 = 0x500D0026 // generic write/all, delete, WRITE_DAC/OWNER, create-link/subkey, set-value
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace == nil {
			return fmt.Errorf("unreadable registry ancestor ACE")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return fmt.Errorf("unsupported registry ancestor ACE")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || uint32(ace.Mask)&writeMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		// CREATOR OWNER is an inheritance placeholder rather than a principal
		// that can acquire rights on this key. Each child is opened and checked
		// independently, so a substituted untrusted child owner still fails.
		if sid.IsValid() && sid.String() == "S-1-3-0" && ace.Header.AceFlags&(windows.CONTAINER_INHERIT_ACE|windows.OBJECT_INHERIT_ACE) != 0 {
			continue
		}
		if !sid.IsValid() || !trusted[sid.String()] {
			return fmt.Errorf("untrusted registry ancestor writer")
		}
	}
	return nil
}

// openRegistryParent opens every component with REG_OPTION_OPEN_LINK and
// keeps handles open. The root is a predefined hive; individual segments must
// never come from an untrusted request or contain registry path separators.
// Existing privileged handles and malicious SYSTEM actors remain out of scope.
func openRegistryParent(root registry.Key, segments []string, trusted map[string]bool) (_ *registryParentLease, err error) {
	if len(segments) == 0 {
		return nil, fmt.Errorf("registry parent path is empty")
	}
	l := &registryParentLease{}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()
	current := root
	for i, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || len(segment) > 255 || bytes.ContainsAny([]byte(segment), "\\/\x00") {
			return nil, fmt.Errorf("invalid registry path segment")
		}
		name, e := windows.UTF16PtrFromString(segment)
		if e != nil {
			return nil, fmt.Errorf("invalid registry path segment")
		}
		access := uint32(registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS | registry.WOW64_64KEY | windows.READ_CONTROL)
		if i == len(segments)-1 {
			access |= registry.CREATE_SUB_KEY
		}
		var h windows.Handle
		if e := windows.RegOpenKeyEx(windows.Handle(current), name, 8, access, &h); e != nil {
			return nil, fmt.Errorf("registry parent unavailable")
		}
		current = registry.Key(h)
		l.handles = append(l.handles, current)
		if err = rejectRegistryLink(current); err != nil {
			return nil, err
		}
		if i == len(segments)-1 {
			err = validateCredentialRegistryKey(current, trusted)
		} else {
			err = validateRegistryAncestor(current, trusted)
		}
		if err != nil {
			return nil, err
		}
	}
	return l, nil
}

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
	r, _, _ := regCredentialCreate.Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, 0, 0, uintptr(registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disposition)))
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
	if err := windows.RegOpenKeyEx(windows.Handle(parent), name, 8, registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL, &h); err != nil {
		return result, fmt.Errorf("registry candidate unavailable")
	}
	k := registry.Key(h)
	defer k.Close()
	if err := validateCredentialRegistryKey(k, trusted); err != nil {
		return result, err
	}
	if err := rejectRegistryLink(k); err != nil {
		return result, err
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

// RunExperimentalCredentialJournal accepts only bounded pipe input. No secret
// is accepted in command-line arguments, environment variables, or errors.
// Its fixed parent must already exist and be provisioned by a trusted installer.
// This entry point is unavailable in normal builds and never authorizes ACK.
func RunExperimentalCredentialJournal(args []string, input io.Reader, output io.Writer) error {
	if len(args) != 1 || (args[0] != "prepare" && args[0] != "read") {
		return fmt.Errorf("invalid journal command")
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	lease, err := openRegistryParent(registry.LOCAL_MACHINE, []string{"SOFTWARE", "TokenTimer", "AgentCredentialJournal"}, trusted)
	if err != nil {
		return fmt.Errorf("journal unavailable")
	}
	defer lease.Close()
	parent := lease.handles[len(lease.handles)-1]
	return runCredentialJournalWithParent(parent, trusted, "O:SYG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)", args, input, output)
}

func runCredentialJournalWithParent(parent registry.Key, trusted map[string]bool, sddl string, args []string, input io.Reader, output io.Writer) error {
	if len(args) != 1 || (args[0] != "prepare" && args[0] != "read") {
		return fmt.Errorf("invalid journal command")
	}
	if args[0] == "prepare" {
		b, err := io.ReadAll(io.LimitReader(input, 513))
		if err != nil || len(b) == 0 || len(b) > 512 {
			return fmt.Errorf("invalid journal request")
		}
		syntax := json.NewDecoder(bytes.NewReader(b))
		if checkJSONValue(syntax, 0) != nil {
			return fmt.Errorf("invalid journal request")
		}
		if _, err := syntax.Token(); err != io.EOF {
			return fmt.Errorf("invalid journal request")
		}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		var rec registryCredentialRecord
		if decoder.Decode(&rec) != nil || !validRegistryCredential(rec) {
			return fmt.Errorf("invalid journal request")
		}
		if err := prepareRegistryCredential(parent, sddl, trusted, rec); err != nil {
			return fmt.Errorf("journal preparation failed")
		}
		_, err = io.WriteString(output, "{\"state\":\"prepared\"}\n")
		return err
	}
	// Read takes no payload; refusing extra input avoids silently accepting a
	// malformed command that may have included sensitive data.
	b, err := io.ReadAll(io.LimitReader(input, 2))
	if err != nil || len(b) != 0 {
		return fmt.Errorf("invalid journal request")
	}
	rec, err := readRegistryCredential(parent, trusted)
	if err != nil {
		return fmt.Errorf("journal recovery failed")
	}
	return json.NewEncoder(output).Encode(rec)
}
