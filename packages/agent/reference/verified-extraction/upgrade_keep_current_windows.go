//go:build windows

package verifiedextraction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"tokentimer-verified-extraction/bootstraplock"
)

// checkKeepCurrentLayout is only a necessary prerequisite. It does not prove
// journal authenticity, actor termination, SCM correctness, or authorization
// to mutate state. The caller must hold and validate the relevant handles.
func checkKeepCurrentLayout(record upgradeRecord, app, previous, staging string) error {
	if record.PreviousIdentity == record.StagingIdentity || record.PreviousIdentity == "" || record.StagingIdentity == "" {
		return fmt.Errorf("ambiguous recorded identities")
	}
	if app != record.StagingIdentity || previous != record.PreviousIdentity || staging != "absent" {
		return fmt.Errorf("ambiguous upgrade layout; preserve state and contact support")
	}
	return nil
}

// openUpgradeJournalForReview holds the real journal as an exclusive barrier.
// No caller may treat the returned record alone as authorization to mutate.
func openUpgradeJournalForReview(path string, policy bootstraplock.Policy) (windows.Handle, upgradeRecord, error) {
	var record upgradeRecord
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, record, fmt.Errorf("invalid upgrade record path")
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, record, fmt.Errorf("exclusive upgrade record unavailable")
	}
	record, err = readProtectedUpgradeRecord(h, policy)
	if err != nil {
		windows.CloseHandle(h)
		return 0, upgradeRecord{}, err
	}
	return h, record, nil
}

// releaseReviewedUpgrade only archives a nominal, operator-reviewed upgrade.
// The caller holds the shared installer mutex. It does not stop processes or
// establish that external actors have stopped; that is an operator obligation.
func releaseReviewedUpgrade(parent, journal, transaction string, parentPolicy, stagePolicy bootstraplock.Policy, sddl string, ackActors, ackKeepCurrent bool, runtimePin identityContract, verifyIdentity func(string, string, identityContract, bootstraplock.Policy) error, service func(string) error, verifyActive func(string, string) (io.Closer, error), renameMarker func(windows.Handle, string, string) error, renameHandle func(windows.Handle, string) error) (string, error) {
	if !ackActors || !ackKeepCurrent || verifyIdentity == nil || service == nil || verifyActive == nil || !stageNamePattern.MatchString("TokenTimer-Staging-"+transaction) {
		return "", fmt.Errorf("explicit operator review and keep-current decision are required")
	}
	unlock, err := lockUpgradeState(journal, parentPolicy, stagePolicy)
	if err != nil {
		return "", err
	}
	defer unlock()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return "", fmt.Errorf("operator identity unavailable")
	}
	journalPolicy := policyWithOperator(stagePolicy, user.User.Sid.String())
	journalHandle, rec, err := openUpgradeJournalForReview(journal, journalPolicy)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(journalHandle)
	binding, err := bindUpgradeJournal(journalHandle)
	if err != nil {
		return "", err
	}
	if err := validateIdentityContract(rec.IdentityContract, runtimePin); err != nil {
		return "", err
	}
	if rec.LauncherIntent != transaction {
		return "", fmt.Errorf("journal transaction does not match")
	}
	root := filepath.Dir(filepath.Dir(journal))
	app := filepath.Join(root, "app")
	previous := app + ".previous." + strconv.Itoa(rec.PID)
	staging := app + ".staging." + strconv.Itoa(rec.PID)
	var dirHandles []windows.Handle
	defer func() {
		for _, h := range dirHandles {
			windows.CloseHandle(h)
		}
	}()
	identityOf := func(path string) (string, error) {
		h, e := lockQuarantineDirectory(path, journalPolicy)
		if e != nil {
			return "", e
		}
		dirHandles = append(dirHandles, h)
		id, e := getDirectoryIdentity(path)
		if e != nil {
			return "", e
		}
		return fmt.Sprintf("%d:%d", id.volume, (uint64(id.indexHigh)<<32)|uint64(id.indexLow)), nil
	}
	appID, err := identityOf(app)
	if err != nil {
		return "", fmt.Errorf("active application unavailable")
	}
	previousID, err := identityOf(previous)
	if err != nil {
		return "", fmt.Errorf("previous application unavailable")
	}
	if _, e := os.Lstat(staging); e == nil || !errors.Is(e, os.ErrNotExist) {
		return "", fmt.Errorf("upgrade staging location is not absent")
	}
	if err = checkKeepCurrentLayout(rec, appID, previousID, "absent"); err != nil {
		return "", err
	}
	if err = verifyIdentity(app, previous, runtimePin, policyWithOperator(parentPolicy, user.User.Sid.String())); err != nil {
		return "", fmt.Errorf("independent identity verification failed")
	}
	if err = service(app); err != nil {
		return "", fmt.Errorf("active service configuration not confirmed")
	}
	if _, e := os.Lstat(staging); !errors.Is(e, os.ErrNotExist) {
		return "", fmt.Errorf("upgrade staging location changed")
	}
	ancestors, err := bootstraplock.LockAncestors(parent, parentPolicy)
	if err != nil {
		return "", fmt.Errorf("untrusted staging parent")
	}
	defer ancestors.Close()
	parentHandle, err := lockQuarantineDirectory(parent, parentPolicy)
	if err != nil {
		return "", fmt.Errorf("untrusted staging parent")
	}
	defer windows.CloseHandle(parentHandle)
	archiveName := "TokenTimer-UpgradeReview-" + transaction
	archive := filepath.Join(parent, archiveName)
	if _, e := os.Lstat(archive); errors.Is(e, os.ErrNotExist) {
		if e = createRestrictedDirectory(archive, sddl); e != nil {
			return "", fmt.Errorf("review archive unavailable")
		}
	} else if e != nil {
		return "", fmt.Errorf("review archive unavailable")
	}
	archiveHandle, err := lockQuarantineDirectory(archive, stagePolicy)
	if err != nil {
		return "", fmt.Errorf("review archive untrusted")
	}
	defer windows.CloseHandle(archiveHandle)
	if validateIntentACL(archiveHandle, &PrivateStaging{policy: stagePolicy}) != nil {
		return "", fmt.Errorf("review archive ACL rejected")
	}
	var archiveInfo, journalInfo windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(archiveHandle, &archiveInfo) != nil || windows.GetFileInformationByHandle(journalHandle, &journalInfo) != nil || archiveInfo.VolumeSerialNumber != journalInfo.VolumeSerialNumber {
		return "", fmt.Errorf("review archive is not on the journal volume")
	}
	sentinel := filepath.Join(parent, "TokenTimer-Staging-"+transaction+".intent")
	approved := filepath.Join(archive, "review-approved.json")
	var records []QuarantineRecord
	var info windows.ByHandleFileInformation
	var activeLock io.Closer
	defer func() {
		if activeLock != nil {
			_ = activeLock.Close()
		}
	}()
	requireActive := func(items []QuarantineRecord) error {
		if len(items) != 2 || items[0].ArchiveSHA256 != items[1].ArchiveSHA256 {
			return fmt.Errorf("launcher inventory digests do not agree")
		}
		lock, e := verifyActive(app, items[0].ArchiveSHA256)
		if e != nil || lock == nil {
			return fmt.Errorf("active application is not independently verified")
		}
		activeLock = lock
		return nil
	}
	if _, e := os.Lstat(sentinel); errors.Is(e, os.ErrNotExist) {
		entries, e := os.ReadDir(archive)
		if e != nil {
			return "", fmt.Errorf("review archive unavailable")
		}
		if len(entries) != 0 {
			declaration, _, e := readReviewSentinel(approved, stagePolicy, transaction, "operator-reviewed-keep-current")
			if e != nil {
				return "", e
			}
			if declaration.Journal == nil || *declaration.Journal != binding {
				return "", fmt.Errorf("reviewed journal identity changed")
			}
			if e = requireActive(declaration.Stages); e != nil {
				return "", e
			}
			validation, e := validateReleaseMarkers(parent, archive, approved, transaction, declaration.Stages, stagePolicy)
			if e != nil {
				return "", e
			}
			defer validation.close()
			if len(validation.pending) != 0 {
				return "", fmt.Errorf("incomplete review archive")
			}
			if _, e = os.Lstat(staging); !errors.Is(e, os.ErrNotExist) {
				return "", fmt.Errorf("upgrade staging location changed")
			}
			if e = renameHandle(journalHandle, filepath.Join(archive, "upgrade-recovery.json")); e != nil {
				return "", fmt.Errorf("journal remains in place")
			}
			return archiveName, nil
		}
		records, e = inspectQuarantinePairWithPolicy(parent, parentPolicy, stagePolicy)
		if e != nil {
			return "", e
		}
		if len(records) != 2 || records[0].Transaction != transaction || records[1].Transaction != transaction {
			return "", fmt.Errorf("launcher transaction mismatch")
		}
		if e = requireActive(records); e != nil {
			return "", e
		}
		info, e = createReviewSentinel(sentinel, sddl, stagePolicy, transaction, records, "operator-reviewed-keep-current", &binding)
		if e != nil {
			return "", e
		}
	} else if e != nil {
		return "", fmt.Errorf("review sentinel unavailable")
	} else {
		declaration, i, e := readReviewSentinel(sentinel, stagePolicy, transaction, "operator-reviewed-keep-current")
		if e != nil {
			return "", e
		}
		if declaration.Journal == nil || *declaration.Journal != binding {
			return "", fmt.Errorf("reviewed journal identity changed")
		}
		records = declaration.Stages
		if e = requireActive(records); e != nil {
			return "", e
		}
		info = i
	}
	validation, err := validateReleaseMarkers(parent, archive, sentinel, transaction, records, stagePolicy)
	if err != nil {
		return "", err
	}
	defer validation.close()
	for _, marker := range validation.pending {
		if err = renameMarker(marker.handle, filepath.Join(parent, marker.name), filepath.Join(archive, marker.name)); err != nil {
			return "", fmt.Errorf("marker archive incomplete; journal and sentinel retained")
		}
	}
	if err = archiveReleaseSentinel(sentinel, approved, info, stagePolicy, renameHandle); err != nil {
		return "", fmt.Errorf("review sentinel retained")
	}
	if _, e := os.Lstat(staging); !errors.Is(e, os.ErrNotExist) {
		return "", fmt.Errorf("upgrade staging location changed; journal retained")
	}
	if err = renameHandle(journalHandle, filepath.Join(archive, "upgrade-recovery.json")); err != nil {
		return "", fmt.Errorf("upgrade journal retained")
	}
	return archiveName, nil
}

// A matching running service is necessary evidence only. It never substitutes
// for explicit review of persistent SCM/WMI actors or identity verification.
func checkKeptAgentService(app string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("TokenTimerAgent")
	if err != nil {
		return err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	state, err := s.Query()
	if err != nil {
		return err
	}
	if state.State != svc.Running || !strings.EqualFold(cfg.BinaryPathName, expectedKeptServiceCommand(app, runtime.GOARCH)) {
		return fmt.Errorf("service does not match the reviewed application")
	}
	// A matching SCM path does not prove the image currently mapped by the
	// process. Until a qualified restart/identity protocol is available, fail.
	return fmt.Errorf("running service image is not independently qualified")
}
func expectedKeptServiceCommand(app, architecture string) string {
	return `"` + filepath.Join(app, "bin", "tokentimer-agent-host-"+architecture+".exe") + `" "` + filepath.Join(app, "runtime", architecture, "node.exe") + `" "` + filepath.Join(app, "bin", "tokentimer-agent.js") + `"`
}

type upgradeJournalBinding struct {
	Volume    uint32 `json:"volume"`
	IndexHigh uint32 `json:"indexHigh"`
	IndexLow  uint32 `json:"indexLow"`
	SHA256    string `json:"sha256"`
}

func bindUpgradeJournal(h windows.Handle) (upgradeJournalBinding, error) {
	var result upgradeJournalBinding
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 4096 {
		return result, fmt.Errorf("journal identity unavailable")
	}
	if _, err := windows.SetFilePointer(h, 0, nil, 0); err != nil {
		return result, fmt.Errorf("journal seek failed")
	}
	b := make([]byte, info.FileSizeLow)
	var n uint32
	if err := windows.ReadFile(h, b, &n, nil); err != nil || n != uint32(len(b)) {
		return result, fmt.Errorf("journal binding failed")
	}
	d := sha256.Sum256(b)
	return upgradeJournalBinding{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow, hex.EncodeToString(d[:])}, nil
}

// The independent pin must come from the authenticated launcher build, never
// from the journal or a neighboring unsigned manifest. Equality alone is not
// a filesystem qualification or an authorization to mutate.
func validateIdentityContract(record *identityContract, independent identityContract) error {
	if record == nil {
		return fmt.Errorf("historical journal lacks an identity contract; support is required")
	}
	if independent.Scheme != "node-fs-win32-v1" || !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(independent.NodeVersion) || (independent.Architecture != "amd64" && independent.Architecture != "arm64") || independent.Architecture != runtime.GOARCH || !digest.MatchString(independent.NodeSHA256) || *record != independent {
		return fmt.Errorf("identity runtime does not match the independent release policy")
	}
	return nil
}
