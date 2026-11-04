//go:build windows

package verifiedextraction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

type releaseDeclaration struct {
	SchemaVersion int                `json:"schemaVersion"`
	Transaction   string             `json:"transaction"`
	OperatorSID   string             `json:"operatorSid"`
	ReviewedAt    string             `json:"reviewedAt"`
	Statement     string             `json:"statement"`
	Stages        []QuarantineRecord `json:"stages"`
}

type releaseBarrierDeclaration struct {
	SchemaVersion int    `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Transaction   string `json:"transaction"`
	OperatorSID   string `json:"operatorSid"`
}

type releaseBarrier struct {
	file *os.File
	info windows.ByHandleFileInformation
}

// ErrQueuedSCMActionProofUnavailable means quarantined paths must be retained.
// Windows can execute an already queued command after a service is disabled or
// its recovery configuration has changed; operator acknowledgement alone does
// not establish that no such action is pending.
var ErrQueuedSCMActionProofUnavailable = errors.New("qualified proof that no queued SCM command or reboot remains is unavailable; retain quarantine and contact support")

// ReleaseQuarantineAfterOperatorReview remains disabled until a trustworthy
// proof of queued SCM action absence is available. Inspection remains usable.
func ReleaseQuarantineAfterOperatorReview(ctx context.Context, transaction string, acknowledged bool) (archive string, err error) {
	if !acknowledged {
		return "", fmt.Errorf("explicit external-actor review is required")
	}
	if err := requireQueuedSCMActionProof(); err != nil {
		return "", err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return "", fmt.Errorf("an elevated token is required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mutex, err := lockInstall(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		if e := unlockInstall(mutex); e != nil {
			archive = ""
			err = e
		}
	}()
	parent, err := nativeProgramFiles()
	if err != nil {
		return "", err
	}
	parents := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true}
	stages := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	return releaseQuarantinePair(parent, `C:\ProgramData\TokenTimerAgent\state\upgrade-recovery.json`, transaction, bootstraplock.Policy{Owners: parents, Writers: parents}, bootstraplock.Policy{Owners: stages, Writers: stages}, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", renameProtectedMarker, renameOpenFile)
}

// No production provider is available. Do not replace this guard with a
// check of the current SCM configuration, service state, or acknowledgement.
func requireQueuedSCMActionProof() error { return ErrQueuedSCMActionProofUnavailable }

// Caller holds the global mutex. If the process dies between moves, a flushed
// sentinel remains in the scanned parent and blocks subsequent installations.
func releaseQuarantinePair(parent, journal, transaction string, parentPolicy, stagePolicy bootstraplock.Policy, sddl string, rename func(windows.Handle, string, string) error, renameHandle func(windows.Handle, string) error) (string, error) {
	if !stageNamePattern.MatchString("TokenTimer-Staging-"+transaction) || rename == nil || renameHandle == nil {
		return "", fmt.Errorf("invalid review transaction")
	}
	releaseJournalLocks, err := lockUpgradeState(journal, parentPolicy, stagePolicy)
	if err != nil {
		return "", err
	}
	defer releaseJournalLocks()
	barrier, err := openReleaseBarrier(journal, transaction, sddl, stagePolicy, false)
	if err != nil {
		return "", err
	}
	defer func() {
		if barrier != nil && barrier.file != nil {
			_ = barrier.file.Close()
		}
	}()
	ancestors, err := bootstraplock.LockAncestors(parent, parentPolicy)
	if err != nil {
		return "", fmt.Errorf("untrusted parent: %w", err)
	}
	defer ancestors.Close()
	parentHandle, err := lockQuarantineDirectory(parent, parentPolicy)
	if err != nil {
		return "", fmt.Errorf("untrusted parent: %w", err)
	}
	defer windows.CloseHandle(parentHandle)
	archiveName := "TokenTimer-Quarantine-" + transaction
	archivePath := filepath.Join(parent, archiveName)
	if _, statErr := os.Lstat(archivePath); os.IsNotExist(statErr) {
		if err := createRestrictedDirectory(archivePath, sddl); err != nil {
			return "", fmt.Errorf("create review archive: %w", err)
		}
	} else if statErr != nil {
		return "", fmt.Errorf("review archive unavailable: %w", statErr)
	}
	archiveHandle, err := lockQuarantineDirectory(archivePath, stagePolicy)
	if err != nil {
		return "", fmt.Errorf("untrusted review archive: %w", err)
	}
	defer windows.CloseHandle(archiveHandle)
	if err := validateIntentACL(archiveHandle, &PrivateStaging{policy: stagePolicy}); err != nil {
		return "", fmt.Errorf("untrusted review archive ACL: %w", err)
	}
	sentinel := filepath.Join(parent, "TokenTimer-Staging-"+transaction+".intent")
	var records []QuarantineRecord
	var info windows.ByHandleFileInformation
	if _, statErr := os.Lstat(sentinel); os.IsNotExist(statErr) {
		entries, err := os.ReadDir(archivePath)
		if err != nil {
			return "", fmt.Errorf("review archive unavailable")
		}
		if len(entries) != 0 {
			approved := filepath.Join(archivePath, "review-approved.json")
			declaration, _, err := readReleaseSentinel(approved, stagePolicy, transaction)
			if err != nil {
				return "", err
			}
			validation, err := validateReleaseMarkers(parent, archivePath, approved, transaction, declaration.Stages, stagePolicy)
			if err != nil {
				return "", err
			}
			defer validation.close()
			if len(validation.pending) != 0 {
				return "", fmt.Errorf("review archive is incomplete")
			}
			archivedBarrierPath := filepath.Join(archivePath, "review-barrier.json")
			if barrier == nil {
				archivedBarrier, err := openReleaseBarrier(archivedBarrierPath, transaction, sddl, stagePolicy, false)
				if err != nil || archivedBarrier == nil {
					return "", fmt.Errorf("review archive barrier unavailable")
				}
				_ = archivedBarrier.file.Close()
				return archiveName, nil
			}
			if err := archiveReleaseBarrier(archivedBarrierPath, barrier, stagePolicy, renameHandle); err != nil {
				return "", fmt.Errorf("upgrade barrier retained: %w", err)
			}
			return archiveName, nil
		}
		records, err = inspectQuarantinePairWithPolicy(parent, parentPolicy, stagePolicy)
		if err != nil {
			return "", err
		}
		if len(records) != 2 || records[0].Transaction != transaction || records[1].Transaction != transaction {
			return "", fmt.Errorf("review transaction does not match protected records")
		}
		if barrier == nil {
			barrier, err = openReleaseBarrier(journal, transaction, sddl, stagePolicy, true)
			if err != nil {
				return "", err
			}
		}
		info, err = createReleaseSentinel(sentinel, sddl, stagePolicy, transaction, records)
		if err != nil {
			return "", err
		}
	} else if statErr != nil {
		return "", fmt.Errorf("review sentinel unavailable: %w", statErr)
	} else {
		var declaration releaseDeclaration
		declaration, info, err = readReleaseSentinel(sentinel, stagePolicy, transaction)
		if err != nil {
			return "", err
		}
		records = declaration.Stages
	}
	if barrier == nil {
		barrier, err = openReleaseBarrier(journal, transaction, sddl, stagePolicy, true)
		if err != nil {
			return "", err
		}
	}
	validation, err := validateReleaseMarkers(parent, archivePath, sentinel, transaction, records, stagePolicy)
	if err != nil {
		return "", err
	}
	defer validation.close()
	var moved []reviewMarker
	for _, marker := range validation.pending {
		if err := rename(marker.handle, filepath.Join(parent, marker.name), filepath.Join(archivePath, marker.name)); err != nil {
			for i := len(moved) - 1; i >= 0; i-- {
				if rollbackErr := rename(moved[i].handle, filepath.Join(archivePath, moved[i].name), filepath.Join(parent, moved[i].name)); rollbackErr != nil {
					return "", fmt.Errorf("marker rollback uncertain; sentinel retained")
				}
			}
			return "", fmt.Errorf("marker archive failed; sentinel retained for retry")
		}
		moved = append(moved, marker)
	}
	if err := archiveReleaseSentinel(sentinel, filepath.Join(archivePath, "review-approved.json"), info, stagePolicy, renameHandle); err != nil {
		return "", fmt.Errorf("markers archived; sentinel retained: %w", err)
	}
	if err := archiveReleaseBarrier(filepath.Join(archivePath, "review-barrier.json"), barrier, stagePolicy, renameHandle); err != nil {
		return "", fmt.Errorf("markers archived; upgrade barrier retained: %w", err)
	}
	return archiveName, nil
}

// Hold protected state ancestors and directories while creating or checking
// the barrier. A missing, linked or unverifiable state directory fails closed.
func lockUpgradeState(journal string, parentPolicy, statePolicy bootstraplock.Policy) (func(), error) {
	if !filepath.IsAbs(journal) || !strings.EqualFold(filepath.Base(journal), "upgrade-recovery.json") {
		return nil, fmt.Errorf("invalid upgrade journal path")
	}
	state := filepath.Dir(journal)
	root := filepath.Dir(state)
	if !strings.EqualFold(filepath.Base(state), "state") || !strings.EqualFold(filepath.Base(root), "TokenTimerAgent") {
		return nil, fmt.Errorf("invalid upgrade state path")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return nil, fmt.Errorf("operator identity unavailable")
	}
	parents := bootstraplock.Policy{Owners: map[string]bool{}, Writers: map[string]bool{}}
	for sid, allowed := range parentPolicy.Owners {
		parents.Owners[sid] = allowed
	}
	for sid, allowed := range parentPolicy.Writers {
		parents.Writers[sid] = allowed
	}
	states := bootstraplock.Policy{Owners: map[string]bool{}, Writers: map[string]bool{}}
	for sid, allowed := range statePolicy.Owners {
		states.Owners[sid] = allowed
	}
	for sid, allowed := range statePolicy.Writers {
		states.Writers[sid] = allowed
	}
	parents.Owners[user.User.Sid.String()] = true
	parents.Writers[user.User.Sid.String()] = true
	states.Owners[user.User.Sid.String()] = true
	states.Writers[user.User.Sid.String()] = true
	ancestors, err := bootstraplock.LockAncestors(state, parents)
	if err != nil {
		return nil, fmt.Errorf("upgrade state unavailable or untrusted: %w", err)
	}
	rootHandle, err := lockDirectoryWithPolicy(root, parents, true)
	if err != nil {
		ancestors.Close()
		return nil, fmt.Errorf("upgrade state root unavailable or untrusted: %w", err)
	}
	stateHandle, err := lockQuarantineDirectory(state, states)
	if err != nil {
		windows.CloseHandle(rootHandle)
		ancestors.Close()
		return nil, fmt.Errorf("upgrade state unavailable or untrusted: %w", err)
	}
	closeLocks := func() { windows.CloseHandle(stateHandle); windows.CloseHandle(rootHandle); ancestors.Close() }
	return closeLocks, nil
}

// A pre-existing ordinary upgrade journal is never modified or removed. The
// temporary barrier uses its exact name so older installers using CREATE_NEW
// cannot create a recovery journal between validation and marker archival.
func openReleaseBarrier(path, transaction, sddl string, policy bootstraplock.Policy, create bool) (*releaseBarrier, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	mode := uint32(windows.OPEN_EXISTING)
	var attrs *windows.SecurityAttributes
	if create {
		mode = windows.CREATE_NEW
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return nil, err
		}
		attrs = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, attrs, mode, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		if !create && (err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND) {
			return nil, nil
		}
		return nil, fmt.Errorf("upgrade recovery journal or barrier unavailable: %w", err)
	}
	f := os.NewFile(uintptr(h), "review-barrier")
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("barrier handle unavailable")
	}
	fail := func(e error) (*releaseBarrier, error) { _ = f.Close(); return nil, e }
	barrier := &releaseBarrier{file: f}
	if err := windows.GetFileInformationByHandle(h, &barrier.info); err != nil || barrier.info.NumberOfLinks != 1 || barrier.info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fail(fmt.Errorf("upgrade barrier identity invalid"))
	}
	if err := validateIntentACL(h, &PrivateStaging{policy: policy}); err != nil {
		return fail(fmt.Errorf("upgrade recovery journal requires support review"))
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return fail(fmt.Errorf("operator identity unavailable"))
	}
	expected := releaseBarrierDeclaration{1, "operator-quarantine-release-barrier", transaction, user.User.Sid.String()}
	if create {
		b, err := json.Marshal(expected)
		if err != nil {
			return fail(err)
		}
		if _, err := f.Write(b); err != nil {
			return fail(err)
		}
		if err := f.Sync(); err != nil {
			return fail(err)
		}
	} else {
		if barrier.info.FileSizeHigh != 0 || barrier.info.FileSizeLow == 0 || barrier.info.FileSizeLow > 4096 {
			return fail(fmt.Errorf("upgrade recovery journal requires support review"))
		}
		b, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(b) == 0 || len(b) > 4096 {
			return fail(fmt.Errorf("upgrade recovery journal requires support review"))
		}
		check := json.NewDecoder(bytes.NewReader(b))
		if err := checkJSONValue(check, 0); err != nil {
			return fail(fmt.Errorf("upgrade recovery journal requires support review"))
		}
		if _, err := check.Token(); err != io.EOF {
			return fail(fmt.Errorf("upgrade recovery journal requires support review"))
		}
		var observed releaseBarrierDeclaration
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&observed); err != nil || observed != expected {
			return fail(fmt.Errorf("upgrade recovery journal requires support review"))
		}
	}
	return barrier, nil
}

func archiveReleaseBarrier(destination string, barrier *releaseBarrier, policy bootstraplock.Policy, renameHandle func(windows.Handle, string) error) error {
	if barrier == nil || barrier.file == nil {
		return fmt.Errorf("upgrade barrier unavailable")
	}
	h := windows.Handle(barrier.file.Fd())
	var got windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &got); err != nil {
		return err
	}
	if err := validateIntentACL(h, &PrivateStaging{policy: policy}); err != nil {
		return err
	}
	if got.VolumeSerialNumber != barrier.info.VolumeSerialNumber || got.FileIndexHigh != barrier.info.FileIndexHigh || got.FileIndexLow != barrier.info.FileIndexLow || got.NumberOfLinks != 1 || got.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("upgrade barrier identity changed")
	}
	if _, err := os.Lstat(destination); err == nil || !os.IsNotExist(err) {
		return fmt.Errorf("upgrade barrier archive destination unavailable")
	}
	if err := renameHandle(h, destination); err != nil {
		return err
	}
	if err := barrier.file.Close(); err != nil {
		return err
	}
	barrier.file = nil
	return nil
}

// Rename the already-opened file without a path-based close/reopen window.
// FILE_RENAME_INFO uses an absolute, non-overwriting name on the same volume.
func renameOpenFile(h windows.Handle, destination string) error {
	if !filepath.IsAbs(destination) {
		return fmt.Errorf("rename destination must be absolute")
	}
	name, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	type fileRenameInfo struct {
		Replace    uint8
		_          [7]byte
		Root       windows.Handle
		NameLength uint32
		Name       [1]uint16
	}
	var header fileRenameInfo
	offset := int(unsafe.Offsetof(header.Name))
	buf := make([]byte, offset+len(name)*2)
	info := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	info.NameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[offset])), len(name)), name)
	return windows.SetFileInformationByHandle(h, windows.FileRenameInfo, &buf[0], uint32(len(buf)))
}

func createReleaseSentinel(path, sddl string, policy bootstraplock.Policy, transaction string, records []QuarantineRecord) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return info, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return info, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, &attrs, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return info, fmt.Errorf("create release sentinel: %w", err)
	}
	defer windows.CloseHandle(h)
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return info, fmt.Errorf("invalid release sentinel")
	}
	if err := validateIntentACL(h, &PrivateStaging{policy: policy}); err != nil {
		return info, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return info, fmt.Errorf("operator identity unavailable")
	}
	declaration, err := json.Marshal(releaseDeclaration{1, transaction, user.User.Sid.String(), time.Now().UTC().Format(time.RFC3339), "operator-reviewed-external-actor-risk", records})
	if err != nil {
		return info, err
	}
	if err := defaultIntentIO().write(h, declaration); err != nil {
		return info, err
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		return info, err
	}
	return info, nil
}

func readReleaseSentinel(path string, policy bootstraplock.Policy, transaction string) (releaseDeclaration, windows.ByHandleFileInformation, error) {
	var declaration releaseDeclaration
	var info windows.ByHandleFileInformation
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return declaration, info, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return declaration, info, err
	}
	f := os.NewFile(uintptr(h), "review-sentinel")
	if f == nil {
		windows.CloseHandle(h)
		return declaration, info, fmt.Errorf("sentinel handle unavailable")
	}
	defer f.Close()
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 4096 {
		return declaration, info, fmt.Errorf("invalid review sentinel")
	}
	if err := validateIntentACL(h, &PrivateStaging{policy: policy}); err != nil {
		return declaration, info, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) == 0 || len(b) > 4096 {
		return declaration, info, fmt.Errorf("review sentinel read failed")
	}
	check := json.NewDecoder(bytes.NewReader(b))
	if err := checkJSONValue(check, 0); err != nil {
		return declaration, info, fmt.Errorf("invalid review sentinel JSON")
	}
	if _, err := check.Token(); err != io.EOF {
		return declaration, info, fmt.Errorf("invalid review sentinel JSON")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&declaration); err != nil {
		return declaration, info, fmt.Errorf("invalid review sentinel schema")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil || declaration.SchemaVersion != 1 || declaration.Transaction != transaction || declaration.OperatorSID != user.User.Sid.String() || declaration.Statement != "operator-reviewed-external-actor-risk" || len(declaration.Stages) != 2 {
		return releaseDeclaration{}, info, fmt.Errorf("review sentinel identity or transaction rejected")
	}
	if _, err := time.Parse(time.RFC3339, declaration.ReviewedAt); err != nil {
		return releaseDeclaration{}, info, fmt.Errorf("invalid review timestamp")
	}
	return declaration, info, nil
}

type reviewMarker struct {
	name   string
	handle windows.Handle
}
type releaseValidation struct {
	pending []reviewMarker
	handles []windows.Handle
}

func (v *releaseValidation) close() {
	for _, h := range v.handles {
		windows.CloseHandle(h)
	}
}
func renameProtectedMarker(h windows.Handle, _, destination string) error {
	return renameOpenFile(h, destination)
}

func validateReleaseMarkers(parent, archive, sentinel, transaction string, expected []QuarantineRecord, policy bootstraplock.Policy) (_ *releaseValidation, err error) {
	validation := &releaseValidation{}
	defer func() {
		if err != nil {
			validation.close()
		}
	}()
	if len(expected) != 2 || expected[0].StageName == expected[1].StageName {
		return nil, fmt.Errorf("invalid review stage set")
	}
	allowedParent := map[string]bool{}
	allowedArchive := map[string]bool{}
	if strings.EqualFold(filepath.Dir(sentinel), parent) {
		allowedParent[strings.ToLower(filepath.Base(sentinel))] = true
	}
	if strings.EqualFold(filepath.Dir(sentinel), archive) {
		allowedArchive[strings.ToLower(filepath.Base(sentinel))] = true
		allowedArchive["review-barrier.json"] = true
	}
	var raw []ExecutionIntent

	for _, item := range expected {
		if !stageNamePattern.MatchString(item.StageName) || item.Transaction != transaction || !digest.MatchString(item.ArchiveSHA256) {
			return nil, fmt.Errorf("invalid reviewed stage")
		}
		stagePath := filepath.Join(parent, item.StageName)
		h, err := lockQuarantineDirectory(stagePath, policy)
		if err != nil {
			return nil, fmt.Errorf("reviewed stage unavailable: %w", err)
		}
		validation.handles = append(validation.handles, h)
		id, err := getDirectoryIdentity(stagePath)
		if err != nil || id.volume != item.Volume || id.indexHigh != item.IndexHigh || id.indexLow != item.IndexLow {
			return nil, fmt.Errorf("reviewed stage identity changed")
		}
		name := item.StageName + ".intent"
		live := filepath.Join(parent, name)
		stored := filepath.Join(archive, name)
		_, liveErr := os.Lstat(live)
		_, archiveErr := os.Lstat(stored)
		if liveErr != nil && !os.IsNotExist(liveErr) || archiveErr != nil && !os.IsNotExist(archiveErr) {
			return nil, fmt.Errorf("reviewed marker unavailable")
		}
		if (liveErr == nil) == (archiveErr == nil) {
			return nil, fmt.Errorf("reviewed marker location ambiguous")
		}
		marker := stored
		if liveErr == nil {
			marker = live

			allowedParent[strings.ToLower(name)] = true
		} else {
			allowedArchive[strings.ToLower(name)] = true
		}
		markerName, err := windows.UTF16PtrFromString(marker)
		if err != nil {
			return nil, err
		}
		markerHandle, err := windows.CreateFile(markerName, windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return nil, fmt.Errorf("reviewed marker unavailable")
		}
		validation.handles = append(validation.handles, markerHandle)
		if liveErr == nil {
			validation.pending = append(validation.pending, reviewMarker{name, markerHandle})
		}
		record, err := inspectQuarantineHandle(&PrivateStaging{path: stagePath, parent: parent, identity: id, policy: policy}, markerHandle)
		if err != nil {
			return nil, err
		}
		raw = append(raw, record)
	}
	summary, err := summarizeQuarantinePair(raw)
	if err != nil {
		return nil, err
	}
	for i := range summary {
		if summary[i] != expected[i] {
			return nil, fmt.Errorf("reviewed marker identity changed")
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		n := strings.ToLower(entry.Name())
		if strings.HasPrefix(n, "tokentimer-staging-") && strings.HasSuffix(n, ".intent") && !allowedParent[n] {
			return nil, fmt.Errorf("unrelated launcher intent remains quarantined")
		}
	}
	archived, err := os.ReadDir(archive)
	if err != nil {
		return nil, err
	}
	for _, entry := range archived {
		if !allowedArchive[strings.ToLower(entry.Name())] {
			return nil, fmt.Errorf("unexpected review archive content")
		}
	}
	return validation, nil
}

func archiveReleaseSentinel(path, destination string, expected windows.ByHandleFileInformation, policy bootstraplock.Policy, renameHandle func(windows.Handle, string) error) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	var got windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &got)
	if err == nil {
		err = validateIntentACL(h, &PrivateStaging{policy: policy})
	}
	defer windows.CloseHandle(h)
	if err != nil || got.VolumeSerialNumber != expected.VolumeSerialNumber || got.FileIndexHigh != expected.FileIndexHigh || got.FileIndexLow != expected.FileIndexLow || got.NumberOfLinks != 1 || got.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("release sentinel identity changed")
	}
	if !strings.HasPrefix(filepath.Base(path), "TokenTimer-Staging-") || !strings.HasSuffix(filepath.Base(path), ".intent") {
		return fmt.Errorf("invalid release sentinel path")
	}
	if _, err := os.Lstat(destination); err == nil || !os.IsNotExist(err) {
		return fmt.Errorf("review evidence destination already exists or unavailable")
	}
	return renameHandle(h, destination)
}
