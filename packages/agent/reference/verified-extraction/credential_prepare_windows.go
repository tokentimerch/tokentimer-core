//go:build windows && credentialprepareexperiment

package verifiedextraction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"unsafe"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

// This experiment only prepares local state. It does not authorize rotation,
// migration, or access on a machine with an uncertain privileged actor. File
// flush does not establish directory durability after a power loss.
const candidateName = "pending-agent-credential.json"

var candidateOperation = regexp.MustCompile(`^[a-f0-9]{32}$`)
var candidateCredential = regexp.MustCompile(`^ttagent_[a-f0-9]{16}_[a-f0-9]{64}$`)

type credentialCandidate struct {
	Version    int    `json:"version"`
	Operation  string `json:"operation"`
	Credential string `json:"credential"`
}

func validCredentialCandidate(c credentialCandidate) bool {
	return c.Version == 1 && candidateOperation.MatchString(c.Operation) && candidateCredential.MatchString(c.Credential)
}

// withCandidateDirectory pins all ancestors and the protected state directory
// while operating on a fixed child. The policy and SDDL must come from trusted
// launcher configuration, not the candidate archive or agent input.
func withCandidateDirectory(dir string, parentPolicy, statePolicy bootstraplock.Policy, fn func(string) error) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("invalid state directory")
	}
	ancestors, err := bootstraplock.LockAncestors(dir, parentPolicy)
	if err != nil {
		return fmt.Errorf("state ancestors unavailable")
	}
	defer ancestors.Close()
	directory, err := lockQuarantineDirectory(dir, statePolicy)
	if err != nil {
		return fmt.Errorf("state directory unavailable")
	}
	defer windows.CloseHandle(directory)
	return fn(filepath.Join(dir, candidateName))
}

func validateCandidateHandle(h windows.Handle, policy bootstraplock.Policy) error {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.FileSizeHigh != 0 || info.FileSizeLow > 512 {
		return fmt.Errorf("invalid candidate identity")
	}
	if validateIntentACL(h, &PrivateStaging{policy: policy}) != nil {
		return fmt.Errorf("untrusted candidate security")
	}
	// The general staging policy checks writers only. Credential contents also
	// require confidentiality: reject every allowed ACE for an untrusted SID,
	// regardless of its mask. A deny ACE never grants access. Reject unknown
	// ACE forms rather than trying to interpret conditional/object permissions.
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("candidate DACL unavailable")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("candidate DACL unavailable")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace == nil {
			return fmt.Errorf("unreadable candidate ACE")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return fmt.Errorf("unsupported candidate ACE")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !policy.Writers[sid.String()] {
			return fmt.Errorf("untrusted candidate reader")
		}
	}
	return nil
}

// prepareCredentialCandidate never replaces an existing file. On any failed
// write or flush it retains the file and refuses further preparation; an
// operator must reconcile it rather than guessing whether it was committed.
func prepareCredentialCandidate(dir, sddl string, parentPolicy, statePolicy bootstraplock.Policy, candidate credentialCandidate) error {
	if !validCredentialCandidate(candidate) {
		return fmt.Errorf("invalid credential candidate")
	}
	return withCandidateDirectory(dir, parentPolicy, statePolicy, func(name string) error {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return fmt.Errorf("invalid candidate security")
		}
		path, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return fmt.Errorf("invalid candidate path")
		}
		attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		h, err := windows.CreateFile(path, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, 0, &attrs, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
		if err != nil {
			return fmt.Errorf("candidate exists or cannot be created")
		}
		defer windows.CloseHandle(h)
		if err := validateCandidateHandle(h, statePolicy); err != nil {
			return err
		}
		b, err := json.Marshal(candidate)
		if err != nil {
			return fmt.Errorf("candidate encoding failed")
		}
		var n uint32
		if windows.WriteFile(h, b, &n, nil) != nil || n != uint32(len(b)) || windows.FlushFileBuffers(h) != nil {
			return fmt.Errorf("candidate write incomplete; retain for reconciliation")
		}
		return nil
	})
}

// readCredentialCandidate opens and validates the same handle before reading;
// sharing denies concurrent writers and deletion until that handle closes.
func readCredentialCandidate(dir string, parentPolicy, statePolicy bootstraplock.Policy) (credentialCandidate, error) {
	var result credentialCandidate
	err := withCandidateDirectory(dir, parentPolicy, statePolicy, func(name string) error {
		path, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return fmt.Errorf("invalid candidate path")
		}
		h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return fmt.Errorf("candidate unavailable")
		}
		defer windows.CloseHandle(h)
		if err := validateCandidateHandle(h, statePolicy); err != nil {
			return err
		}
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileSizeLow == 0 {
			return fmt.Errorf("incomplete candidate")
		}
		b := make([]byte, info.FileSizeLow)
		var n uint32
		if windows.ReadFile(h, b, &n, nil) != nil || n != uint32(len(b)) {
			return fmt.Errorf("candidate read failed")
		}
		syntax := json.NewDecoder(bytes.NewReader(b))
		if checkJSONValue(syntax, 0) != nil {
			return fmt.Errorf("invalid candidate encoding")
		}
		if _, err := syntax.Token(); err != io.EOF {
			return fmt.Errorf("invalid candidate encoding")
		}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		var record credentialCandidate
		if decoder.Decode(&record) != nil || !validCredentialCandidate(record) {
			return fmt.Errorf("invalid candidate record")
		}
		result = record
		return nil
	})
	return result, err
}
