//go:build windows

package verifiedextraction

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"tokentimer-verified-extraction/bootstraplock"
	"unsafe"
)

type restartJournalHeader struct {
	Kind              string                `json:"kind"`
	Transaction       string                `json:"transaction"`
	OperatorSID       string                `json:"operatorSid"`
	Journal           upgradeJournalBinding `json:"journal"`
	Mode              string                `json:"mode,omitempty"`
	OriginalStartType uint32                `json:"originalStartType,omitempty"`
}
type protectedRestartJournal struct {
	file           *os.File
	size           int64
	stopRequested  bool
	resumedBlocked bool
	progress       restartProgress
}

func (j *protectedRestartJournal) CanRestart() bool { return !j.stopRequested }
func (j *protectedRestartJournal) Close() error     { return j.file.Close() }
func (j *protectedRestartJournal) FlushStep(step string) error {
	if j.resumedBlocked {
		return fmt.Errorf("interrupted stop requires manual review")
	}
	next, err := advanceRestartProgress(j.progress, step)
	if err != nil {
		return err
	}
	line := []byte(step + "\n")
	if j.size+int64(len(line)) > 64<<10 {
		return fmt.Errorf("restart journal is full")
	}
	n, err := j.file.Write(line)
	if err != nil || n != len(line) {
		return fmt.Errorf("restart journal write failed")
	}
	if err = j.file.Sync(); err != nil {
		return fmt.Errorf("restart journal flush failed")
	}
	j.size += int64(n)
	j.progress = next
	if next.phase > 0 {
		j.stopRequested = true
	}
	return nil
}
func openProtectedRestartJournal(archive, sddl, transaction string, binding upgradeJournalBinding, policy bootstraplock.Policy) (*protectedRestartJournal, error) {
	return openRestartJournal(archive, sddl, transaction, binding, policy, "", 0)
}
func openDisableStopJournal(archive, sddl, transaction string, binding upgradeJournalBinding, policy bootstraplock.Policy, originalStartType uint32) (*protectedRestartJournal, error) {
	if originalStartType != windows.SERVICE_AUTO_START && originalStartType != windows.SERVICE_DEMAND_START {
		return nil, fmt.Errorf("unsupported original start type")
	}
	return openRestartJournal(archive, sddl, transaction, binding, policy, "disable-and-stop-v1", originalStartType)
}
func openRestartJournal(archive, sddl, transaction string, binding upgradeJournalBinding, policy bootstraplock.Policy, mode string, originalStartType uint32) (j *protectedRestartJournal, err error) {
	if !stageNamePattern.MatchString("TokenTimer-Staging-" + transaction) {
		return nil, fmt.Errorf("invalid transaction")
	}
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || token.User.Sid == nil {
		return nil, fmt.Errorf("operator identity unavailable")
	}
	expected := restartJournalHeader{Kind: "review-restart-v1", Transaction: transaction, OperatorSID: token.User.Sid.String(), Journal: binding, Mode: mode, OriginalStartType: originalStartType}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(filepath.Join(archive, "restart-review.log"))
	if err != nil {
		return nil, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, &attrs, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	created := err == nil
	if err == windows.ERROR_FILE_EXISTS || err == windows.ERROR_ALREADY_EXISTS {
		h, err = windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("restart journal unavailable")
	}
	f := os.NewFile(uintptr(h), "restart-review")
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("restart journal handle unavailable")
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.FileSizeHigh != 0 || info.FileSizeLow > 64<<10 {
		return nil, fmt.Errorf("invalid restart journal identity")
	}
	if validateIntentACL(h, &PrivateStaging{policy: policy}) != nil {
		return nil, fmt.Errorf("untrusted restart journal ACL")
	}
	if created {
		header, e := json.Marshal(expected)
		if e != nil {
			return nil, e
		}
		header = append(header, '\n')
		n, e := f.Write(header)
		if e != nil || n != len(header) {
			return nil, fmt.Errorf("restart journal header write failed")
		}
		if e = f.Sync(); e != nil {
			return nil, fmt.Errorf("restart journal header flush failed")
		}
		return &protectedRestartJournal{file: f, size: int64(n), progress: restartProgress{mode: mode}}, nil
	}
	raw, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if e != nil || len(raw) == 0 || len(raw) > 64<<10 || raw[len(raw)-1] != '\n' {
		return nil, fmt.Errorf("invalid restart journal content")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	if !scanner.Scan() {
		return nil, fmt.Errorf("restart journal header missing")
	}
	var actual restartJournalHeader
	check := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
	if checkJSONValue(check, 0) != nil {
		return nil, fmt.Errorf("invalid restart journal header")
	}
	if _, e := check.Token(); e != io.EOF {
		return nil, fmt.Errorf("invalid restart journal header")
	}
	d := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(&actual) != nil || actual != expected {
		return nil, fmt.Errorf("restart journal binding mismatch")
	}
	progress := restartProgress{mode: mode}
	for scanner.Scan() {
		next, e := advanceRestartProgress(progress, scanner.Text())
		if e != nil {
			return nil, fmt.Errorf("invalid restart journal sequence")
		}
		progress = next
	}
	stopRequested := progress.phase > 0
	if scanner.Err() != nil {
		return nil, fmt.Errorf("invalid restart journal content")
	}
	if _, e = f.Seek(0, io.SeekEnd); e != nil {
		return nil, fmt.Errorf("restart journal seek failed")
	}
	return &protectedRestartJournal{file: f, size: int64(len(raw)), stopRequested: stopRequested, resumedBlocked: stopRequested, progress: progress}, nil
}

type restartProgress struct {
	phase    int
	observed bool
	mode     string
}

func advanceRestartProgress(p restartProgress, step string) (restartProgress, error) {
	switch p.phase {
	case 0:
		if step == "verify-before" {
			p.observed = true
			return p, nil
		}
		if step == "disable-requested" && p.observed && p.mode == "disable-and-stop-v1" {
			p.phase = 7
			return p, nil
		}
		if step == "stop-requested" && p.observed && p.mode == "" {
			p.phase = 1
			return p, nil
		}
	case 7:
		if step == "verify-disabled" && p.mode == "disable-and-stop-v1" {
			p.phase = 8
			return p, nil
		}
	case 8:
		if step == "stop-requested" && p.mode == "disable-and-stop-v1" {
			p.phase = 1
			return p, nil
		}
	case 1:
		if step == "verify-stopped" {
			p.phase = 2
			return p, nil
		}
	case 2:
		if step == "stopped-verified" {
			p.phase = 6
			return p, nil
		}
		if step == "start-requested" && p.mode == "" {
			p.phase = 3
			return p, nil
		}
	case 3:
		if step == "verify-started" {
			p.phase = 4
			return p, nil
		}
	case 4:
		if step == "verified" {
			p.phase = 5
			return p, nil
		}
	}
	return p, fmt.Errorf("invalid restart journal sequence")
}
