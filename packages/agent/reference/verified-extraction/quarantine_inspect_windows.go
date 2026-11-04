//go:build windows

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

// InspectQuarantine reports protected staging identities without releasing,
// deleting or modifying anything. Its output cannot authorize recovery.
func InspectQuarantine(ctx context.Context) (records []QuarantineRecord, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mutex, err := lockInstall(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if e := unlockInstall(mutex); e != nil {
			records = nil
			err = e
		}
	}()
	parent, err := nativeProgramFiles()
	if err != nil {
		return nil, err
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true}
	stageTrusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	return inspectQuarantinePairWithPolicy(parent, bootstraplock.Policy{Owners: trusted, Writers: trusted}, bootstraplock.Policy{Owners: stageTrusted, Writers: stageTrusted})
}

// QuarantineRecord deliberately excludes the pipe secret and service
// environment. Inspection is not evidence that external actors have stopped.
type QuarantineRecord struct {
	StageName     string `json:"stageName"`
	Volume        uint32 `json:"volume"`
	IndexHigh     uint32 `json:"indexHigh"`
	IndexLow      uint32 `json:"indexLow"`
	Transaction   string `json:"transaction"`
	ArchiveSHA256 string `json:"archiveSha256"`
}

// inspectQuarantineRecord reads one bounded, protected marker using a handle
// that denies replacement and writing. It never mutates or releases a stage.
func inspectQuarantineRecord(stage *PrivateStaging) (ExecutionIntent, error) {
	var result ExecutionIntent
	name, err := windows.UTF16PtrFromString(stage.path + ".intent")
	if err != nil {
		return result, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return result, fmt.Errorf("open protected marker: %w", err)
	}
	f := os.NewFile(uintptr(h), "protected-intent")
	if f == nil {
		windows.CloseHandle(h)
		return result, fmt.Errorf("marker handle unavailable")
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 4096 {
		return result, fmt.Errorf("invalid marker identity or size")
	}
	if err := validateIntentACL(h, stage); err != nil {
		return result, fmt.Errorf("invalid marker ACL")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) == 0 || len(b) > 4096 {
		return result, fmt.Errorf("marker read failed")
	}
	check := json.NewDecoder(bytes.NewReader(b))
	if err := checkJSONValue(check, 0); err != nil {
		return result, fmt.Errorf("invalid marker JSON")
	}
	if _, err := check.Token(); err != io.EOF {
		return result, fmt.Errorf("invalid marker JSON")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&result); err != nil {
		return ExecutionIntent{}, fmt.Errorf("invalid marker schema")
	}
	id, err := getDirectoryIdentity(stage.path)
	if err != nil || id != stage.identity || result.SchemaVersion != 1 || result.Phase != "execution-intent" || result.StageName != filepath.Base(stage.path) || result.Volume != id.volume || result.IndexHigh != id.indexHigh || result.IndexLow != id.indexLow || !stageNamePattern.MatchString("TokenTimer-Staging-"+result.Transaction) || !digest.MatchString(result.Secret) || !digest.MatchString(result.ArchiveSHA256) || !digest.MatchString(result.PreviousSCMSHA256) {
		return ExecutionIntent{}, fmt.Errorf("marker and staging identity do not match")
	}
	return result, nil
}

// inspectQuarantinePairWithPolicy is read-only and does not infer that a
// missing record, an OS restart, a PID, or a stopped service is safe to clean.
func inspectQuarantinePairWithPolicy(parent string, parentPolicy, stagePolicy bootstraplock.Policy) ([]QuarantineRecord, error) {
	if !filepath.IsAbs(parent) {
		return nil, fmt.Errorf("invalid quarantine parent")
	}
	ancestor, err := bootstraplock.LockAncestors(parent, parentPolicy)
	if err != nil {
		return nil, fmt.Errorf("untrusted quarantine parent: %w", err)
	}
	defer ancestor.Close()
	parentHandle, err := lockQuarantineDirectory(parent, parentPolicy)
	if err != nil {
		return nil, fmt.Errorf("untrusted quarantine parent: %w", err)
	}
	defer windows.CloseHandle(parentHandle)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, err
	}
	names, err := quarantineMarkerNames(entries)
	if err != nil {
		return nil, err
	}
	var raw []ExecutionIntent
	var locks []windows.Handle
	defer func() {
		for _, l := range locks {
			windows.CloseHandle(l)
		}
	}()
	for _, name := range names {
		stageName := strings.TrimSuffix(name, ".intent")
		if !stageNamePattern.MatchString(stageName) {
			return nil, fmt.Errorf("invalid protected stage name")
		}
		stagePath := filepath.Join(parent, stageName)
		l, err := lockQuarantineDirectory(stagePath, stagePolicy)
		if err != nil {
			return nil, fmt.Errorf("untrusted stage: %w", err)
		}
		locks = append(locks, l)
		id, err := getDirectoryIdentity(stagePath)
		if err != nil {
			return nil, err
		}
		item, err := inspectQuarantineRecord(&PrivateStaging{path: stagePath, parent: parent, identity: id, policy: stagePolicy})
		if err != nil {
			return nil, err
		}
		raw = append(raw, item)
	}
	return summarizeQuarantinePair(raw)
}

func quarantineMarkerNames(entries []os.DirEntry) ([]string, error) {
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(strings.ToLower(name), "tokentimer-staging-") && strings.HasSuffix(strings.ToLower(name), ".intent") {
			if !strings.HasSuffix(name, ".intent") || !stageNamePattern.MatchString(strings.TrimSuffix(name, ".intent")) {
				return nil, fmt.Errorf("invalid protected stage name")
			}
			names = append(names, name)
		}
	}
	if len(names) != 2 {
		return nil, fmt.Errorf("exactly two protected intents are required")
	}
	return names, nil
}

// Lock only the directory identity, not the contained files: a diagnostic
// must not block writes by a still-running privileged actor inside the stage.
func lockQuarantineDirectory(path string, policy bootstraplock.Policy) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("invalid stage directory")
	}
	if err := policy.ValidateHandle(syscall.Handle(h), false); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

func summarizeQuarantinePair(raw []ExecutionIntent) ([]QuarantineRecord, error) {
	if len(raw) != 2 || raw[0].Transaction != raw[1].Transaction || raw[0].Secret != raw[1].Secret || raw[0].ArchiveSHA256 != raw[1].ArchiveSHA256 || raw[0].PreviousSCMSHA256 != raw[1].PreviousSCMSHA256 || (raw[0].Volume == raw[1].Volume && raw[0].IndexHigh == raw[1].IndexHigh && raw[0].IndexLow == raw[1].IndexLow) {
		return nil, fmt.Errorf("protected intents do not form a pair")
	}
	result := make([]QuarantineRecord, 0, 2)
	for _, item := range raw {
		result = append(result, QuarantineRecord{StageName: item.StageName, Volume: item.Volume, IndexHigh: item.IndexHigh, IndexLow: item.IndexLow, Transaction: item.Transaction, ArchiveSHA256: item.ArchiveSHA256})
	}
	return result, nil
}
