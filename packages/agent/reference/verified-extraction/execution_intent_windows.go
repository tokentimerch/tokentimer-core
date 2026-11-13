//go:build windows

package verifiedextraction

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrExecutionRecoveryPending means manual reconciliation remains necessary.
// A marker, even a valid one, cannot prove that WMI or SCM actors have ended.
var ErrExecutionRecoveryPending = errors.New("execution recovery requires manual reconciliation")

// ExecutionIntent is an immutable protected pre-execution record. Secret must
// never be logged or placed in a process environment. It is not evidence of
// success and never authorizes automatic cleanup.
type ExecutionIntent struct {
	SchemaVersion     int    `json:"schemaVersion"`
	Phase             string `json:"phase"`
	StageName         string `json:"stageName"`
	Volume            uint32 `json:"volume"`
	IndexHigh         uint32 `json:"indexHigh"`
	IndexLow          uint32 `json:"indexLow"`
	Transaction       string `json:"transaction"`
	Secret            string `json:"secret"`
	ArchiveSHA256     string `json:"archiveSha256"`
	PreviousSCMSHA256 string `json:"previousScmSha256"`
}

type intentIO struct {
	write func(windows.Handle, []byte) error
	flush func(windows.Handle) error
}

func defaultIntentIO() intentIO {
	return intentIO{write: func(h windows.Handle, data []byte) error {
		var n uint32
		if err := windows.WriteFile(h, data, &n, nil); err != nil {
			return err
		}
		if int(n) != len(data) {
			return io.ErrShortWrite
		}
		return nil
	}, flush: windows.FlushFileBuffers}
}

// BeginExecutionIntent must succeed before the first installer process starts.
// The SCM digest is computed independently by the caller without storing
// secrets here. This experimental API is not wired into a release launcher.
// FlushFileBuffers establishes the file write for a process-crash scenario; it
// does not claim directory durability across power loss or reboot.
func (p *Prepared) BeginExecutionIntent(previousSCMSHA256 string) (ExecutionIntent, error) {
	if p == nil || p.staging == nil {
		return ExecutionIntent{}, fmt.Errorf("prepared staging unavailable")
	}
	return p.staging.beginExecutionIntent(p.manifest.Archive.SHA256, previousSCMSHA256,
		"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", defaultIntentIO())
}

func (s *PrivateStaging) beginExecutionIntent(archiveSHA256, scmSHA256, sddl string, op intentIO) (result ExecutionIntent, err error) {
	return s.beginExecutionIntentForTransaction(archiveSHA256, scmSHA256, sddl, "", "", op)
}

func (s *PrivateStaging) beginExecutionIntentForTransaction(archiveSHA256, scmSHA256, sddl, transaction, secret string, op intentIO) (result ExecutionIntent, err error) {
	s.intentMu.Lock()
	defer s.intentMu.Unlock()
	if s.ancestors == nil || s.staging == nil || s.payload == nil || !s.freshOwned || s.intentAttempted ||
		!filepath.IsAbs(s.path) || !stringsEqualPath(filepath.Dir(s.path), s.parent) ||
		!stageNamePattern.MatchString(filepath.Base(s.path)) || !digest.MatchString(archiveSHA256) || !digest.MatchString(scmSHA256) || op.write == nil || op.flush == nil {
		return result, fmt.Errorf("invalid protected execution intent")
	}
	id, err := getDirectoryIdentity(s.path)
	if err != nil || id != s.identity || id.indexHigh == 0 && id.indexLow == 0 {
		return result, fmt.Errorf("staging identity unavailable or changed")
	}
	if transaction == "" {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return result, err
		}
		transaction = hex.EncodeToString(nonce[:])
	}
	if !stageNamePattern.MatchString("TokenTimer-Staging-" + transaction) {
		return result, fmt.Errorf("invalid intent transaction")
	}
	if secret == "" {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return result, err
		}
		secret = hex.EncodeToString(nonce[:])
	}
	if !digest.MatchString(secret) {
		return result, fmt.Errorf("invalid intent secret")
	}
	result = ExecutionIntent{SchemaVersion: 1, Phase: "execution-intent", StageName: filepath.Base(s.path), Volume: id.volume, IndexHigh: id.indexHigh, IndexLow: id.indexLow, Transaction: transaction, Secret: secret, ArchiveSHA256: archiveSHA256, PreviousSCMSHA256: scmSHA256}
	data, err := json.Marshal(result)
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return ExecutionIntent{}, fmt.Errorf("invalid intent size")
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return ExecutionIntent{}, err
	}
	name, err := windows.UTF16PtrFromString(s.path + ".intent")
	if err != nil {
		return ExecutionIntent{}, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	// Set before CREATE_NEW. Even an uncertain or partial I/O result prevents
	// later cleanup by this instance; a child must not be launched on error.
	s.intentAttempted = true
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ, &attrs, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return ExecutionIntent{}, fmt.Errorf("create protected intent: %w", err)
	}
	defer func() {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
	}()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return ExecutionIntent{}, fmt.Errorf("invalid intent file identity")
	}
	if err := validateIntentACL(h, s); err != nil {
		return ExecutionIntent{}, err
	}
	if err := op.write(h, data); err != nil {
		return ExecutionIntent{}, fmt.Errorf("write intent: %w", err)
	}
	if err := op.flush(h); err != nil {
		return ExecutionIntent{}, fmt.Errorf("flush intent: %w", err)
	}
	if err := windows.CloseHandle(h); err != nil {
		return ExecutionIntent{}, fmt.Errorf("close intent: %w", err)
	}
	h = 0
	s.intentFlushed = true
	return result, nil
}

func stringsEqualPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func validateIntentACL(h windows.Handle, s *PrivateStaging) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("intent security unavailable: %w", err)
	}
	flags, _, err := sd.Control()
	if err != nil || flags&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("intent DACL is not protected")
	}
	if err := s.policy.ValidateHandle(syscall.Handle(h), false); err != nil {
		return fmt.Errorf("intent security rejected: %w", err)
	}
	return nil
}

// inspectExecutionIntent only provides bounded diagnostic data for a trusted,
// locked stage; it always returns ErrExecutionRecoveryPending, including when
// the record is well formed. It never replays work, removes files or proves the
// publisher, a boot change, or the termination of external privileged actors.
func (s *PrivateStaging) inspectExecutionIntent(archiveSHA256, scmSHA256 string) (ExecutionIntent, bool, error) {
	record, err := s.inspectExecutionIntentRecord(archiveSHA256, scmSHA256)
	return record, record != (ExecutionIntent{}), err
}

func (s *PrivateStaging) inspectExecutionIntentRecord(archiveSHA256, scmSHA256 string) (ExecutionIntent, error) {
	s.intentMu.Lock()
	defer s.intentMu.Unlock()
	var result ExecutionIntent
	if s.ancestors == nil || s.staging == nil || !filepath.IsAbs(s.path) || !stringsEqualPath(filepath.Dir(s.path), s.parent) || !stageNamePattern.MatchString(filepath.Base(s.path)) || !digest.MatchString(archiveSHA256) || !digest.MatchString(scmSHA256) {
		return result, ErrExecutionRecoveryPending
	}
	id, err := getDirectoryIdentity(s.path)
	if err != nil || id != s.identity {
		return result, ErrExecutionRecoveryPending
	}
	name, err := windows.UTF16PtrFromString(s.path + ".intent")
	if err != nil {
		return result, ErrExecutionRecoveryPending
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return result, ErrExecutionRecoveryPending
	}
	f := os.NewFile(uintptr(h), "execution-intent")
	if f == nil {
		windows.CloseHandle(h)
		return result, ErrExecutionRecoveryPending
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 4096 {
		return result, ErrExecutionRecoveryPending
	}
	if err := validateIntentACL(h, s); err != nil {
		return result, ErrExecutionRecoveryPending
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return result, ErrExecutionRecoveryPending
	}
	check := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(check, 0); err != nil {
		return result, ErrExecutionRecoveryPending
	}
	if _, err := check.Token(); err != io.EOF {
		return result, ErrExecutionRecoveryPending
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&result); err != nil {
		return ExecutionIntent{}, ErrExecutionRecoveryPending
	}
	if result.SchemaVersion != 1 || result.Phase != "execution-intent" || result.StageName != filepath.Base(s.path) || result.Volume != id.volume || result.IndexHigh != id.indexHigh || result.IndexLow != id.indexLow || len(result.Transaction) != 32 || !stageNamePattern.MatchString("TokenTimer-Staging-"+result.Transaction) || !digest.MatchString(result.Secret) || result.ArchiveSHA256 != archiveSHA256 || result.PreviousSCMSHA256 != scmSHA256 {
		return ExecutionIntent{}, ErrExecutionRecoveryPending
	}
	return result, ErrExecutionRecoveryPending
}
