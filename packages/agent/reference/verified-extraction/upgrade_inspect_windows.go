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
	"regexp"
	"runtime"
	"strconv"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"tokentimer-verified-extraction/bootstraplock"
)

type upgradeRecord struct {
	Version                       int             `json:"version"`
	PID                           int             `json:"pid"`
	PreviousIdentity              string          `json:"previousIdentity"`
	StagingIdentity               string          `json:"stagingIdentity"`
	PreviousServicePath           string          `json:"previousServicePath"`
	PreviousServiceDisplayName    string          `json:"previousServiceDisplayName"`
	PreviousServiceStartMode      string          `json:"previousServiceStartMode"`
	HadPreviousServiceEnvironment bool            `json:"hadPreviousServiceEnvironment"`
	PreviousServiceEnvironment    json.RawMessage `json:"previousServiceEnvironment"`
	LauncherIntent                string          `json:"launcherIntent"`
}

type UpgradeInspection struct {
	Transaction              string `json:"transaction"`
	RecordedPreviousIdentity string `json:"recordedPreviousIdentity"`
	RecordedStagingIdentity  string `json:"recordedStagingIdentity"`
	Application              string `json:"application"`
	Previous                 string `json:"previous"`
	Staging                  string `json:"staging"`
	ServiceState             string `json:"serviceState"`
	Classification           string `json:"classification"`
	Notice                   string `json:"notice"`
}

// InspectUpgradeRecovery makes no recovery decision and never releases state.
func InspectUpgradeRecovery(ctx context.Context) (report UpgradeInspection, err error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return report, fmt.Errorf("an elevated token is required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mutex, err := lockInstall(ctx)
	if err != nil {
		return report, err
	}
	defer func() {
		if e := unlockInstall(mutex); e != nil {
			report = UpgradeInspection{}
			err = e
		}
	}()
	parent := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true}
	strict := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	root := `C:\ProgramData\TokenTimerAgent`
	return inspectUpgradeRecovery(root, bootstraplock.Policy{Owners: parent, Writers: parent}, bootstraplock.Policy{Owners: strict, Writers: strict}, readServiceState)
}

func inspectUpgradeRecovery(root string, parentPolicy, statePolicy bootstraplock.Policy, service func() (string, error)) (UpgradeInspection, error) {
	var out UpgradeInspection
	journal := filepath.Join(root, "state", "upgrade-recovery.json")
	unlock, err := lockUpgradeState(journal, parentPolicy, statePolicy)
	if err != nil {
		return out, fmt.Errorf("protected state unavailable")
	}
	defer unlock()
	name, err := windows.UTF16PtrFromString(journal)
	if err != nil {
		return out, fmt.Errorf("invalid journal path")
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return out, fmt.Errorf("protected upgrade record unavailable")
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 4096 {
		return out, fmt.Errorf("invalid upgrade record identity or size")
	}
	// The installer explicitly grants its current elevated SID access to the
	// journal. Only this process's own SID is added; a different installer's
	// personal SID still fails closed and requires support.
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return out, fmt.Errorf("operator identity unavailable")
	}
	journalPolicy := policyWithOperator(statePolicy, user.User.Sid.String())
	if validateIntentACL(h, &PrivateStaging{policy: journalPolicy}) != nil {
		return out, fmt.Errorf("untrusted upgrade record ACL")
	}
	b := make([]byte, info.FileSizeLow)
	var n uint32
	if err = windows.ReadFile(h, b, &n, nil); err != nil || n != uint32(len(b)) {
		return out, fmt.Errorf("upgrade record read failed")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if checkJSONValue(d, 0) != nil {
		return out, fmt.Errorf("invalid upgrade record JSON")
	}
	if _, e := d.Token(); e != io.EOF {
		return out, fmt.Errorf("invalid upgrade record JSON")
	}
	var rec upgradeRecord
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&rec) != nil {
		return out, fmt.Errorf("invalid upgrade record schema")
	}
	identity := regexp.MustCompile(`^\d+:[1-9]\d*$`)
	if rec.Version != 1 || rec.PID <= 0 || rec.PID > 2147483647 || !identity.MatchString(rec.PreviousIdentity) || !identity.MatchString(rec.StagingIdentity) || !stageNamePattern.MatchString("TokenTimer-Staging-"+rec.LauncherIntent) || rec.PreviousServicePath == "" || rec.PreviousServiceDisplayName == "" || (rec.PreviousServiceStartMode != "Automatic" && rec.PreviousServiceStartMode != "Manual" && rec.PreviousServiceStartMode != "Disabled") {
		return out, fmt.Errorf("unsupported upgrade record")
	}
	out.Transaction = rec.LauncherIntent
	out.RecordedPreviousIdentity = rec.PreviousIdentity
	out.RecordedStagingIdentity = rec.StagingIdentity
	// The installer records Node.js stat identities; report native identities only,
	// without assuming that the two representations are interchangeable.
	var directoryHandles []windows.Handle
	defer func() {
		for _, handle := range directoryHandles {
			windows.CloseHandle(handle)
		}
	}()
	for _, item := range []struct {
		name string
		dest *string
	}{{"app", &out.Application}, {"app.previous." + strconv.Itoa(rec.PID), &out.Previous}, {"app.staging." + strconv.Itoa(rec.PID), &out.Staging}} {
		path := filepath.Join(root, item.name)
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			*item.dest = "absent"
			continue
		}
		if err != nil {
			return UpgradeInspection{}, fmt.Errorf("application location unavailable")
		}
		lock, err := lockQuarantineDirectory(path, journalPolicy)
		if err != nil {
			return UpgradeInspection{}, fmt.Errorf("application location untrusted")
		}
		directoryHandles = append(directoryHandles, lock)
		id, err := getDirectoryIdentity(path)
		if err != nil {
			return UpgradeInspection{}, fmt.Errorf("application identity unavailable")
		}
		*item.dest = fmt.Sprintf("%d:%d", id.volume, (uint64(id.indexHigh)<<32)|uint64(id.indexLow))
	}
	out.ServiceState, err = service()
	if err != nil {
		return UpgradeInspection{}, fmt.Errorf("service state unavailable")
	}
	out.Classification = classifyUpgradePresence(out.Application, out.Previous, out.Staging)
	out.Notice = "Read-only, non-atomic observation; classification describes presence only and does not prove identity equivalence, health, actor termination or authorize recovery. Preserve the journal, application and staging; contact support."
	return out, nil
}

func readServiceState() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	s, err := m.OpenService("TokenTimerAgent")
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "absent", nil
	}
	if err != nil {
		return "", err
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return "", err
	}
	switch status.State {
	case svc.Stopped:
		return "stopped", nil
	case svc.StartPending:
		return "start-pending", nil
	case svc.StopPending:
		return "stop-pending", nil
	case svc.Running:
		return "running", nil
	case svc.ContinuePending:
		return "continue-pending", nil
	case svc.PausePending:
		return "pause-pending", nil
	case svc.Paused:
		return "paused", nil
	default:
		return "unknown", nil
	}
}

func policyWithOperator(policy bootstraplock.Policy, sid string) bootstraplock.Policy {
	result := bootstraplock.Policy{Owners: map[string]bool{}, Writers: map[string]bool{}}
	for k, v := range policy.Owners {
		result.Owners[k] = v
	}
	for k, v := range policy.Writers {
		result.Writers[k] = v
	}
	result.Owners[sid] = true
	result.Writers[sid] = true
	return result
}

// Classification describes only observed directory presence, never identities,
// success, health or permission to act. Absent paths are not locked.
func classifyUpgradePresence(app, previous, staging string) string {
	present := func(s string) bool { return s != "" && s != "absent" }
	absent := func(s string) bool { return s == "absent" }
	switch {
	case present(app) && present(previous) && absent(staging):
		return "app-and-backup-present-unverified"
	case present(app) && absent(previous) && present(staging):
		return "app-and-staging-present-unverified"
	case absent(app) && present(previous) && present(staging):
		return "backup-and-staging-present-unverified"
	default:
		return "ambiguous-manual-review-required"
	}
}
