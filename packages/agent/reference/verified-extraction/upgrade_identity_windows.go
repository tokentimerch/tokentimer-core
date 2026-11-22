//go:build windows

package verifiedextraction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

// verifyIdentityRuntime executes only an independently pinned, locked Node
// binary and a fixed built-in script, with an explicit environment. This is
// still a prerequisite, not evidence that external actors have stopped.
func verifyIdentityRuntime(app, previous string, pin identityContract, parentPolicy bootstraplock.Policy) error {
	if pin.Scheme != "node-fs-win32-v1" || !digest.MatchString(pin.NodeSHA256) || (pin.Architecture != "amd64" && pin.Architecture != "arm64") {
		return fmt.Errorf("invalid identity runtime policy")
	}
	appID, err := getDirectoryIdentity(app)
	if err != nil {
		return fmt.Errorf("active identity unavailable")
	}
	previousID, err := getDirectoryIdentity(previous)
	if err != nil {
		return fmt.Errorf("backup identity unavailable")
	}
	if appID.volume != previousID.volume {
		return fmt.Errorf("application volumes differ")
	}
	pathPtr, err := windows.UTF16PtrFromString(app)
	if err != nil {
		return fmt.Errorf("invalid application path")
	}
	var volumePath [windows.MAX_PATH]uint16
	if err = windows.GetVolumePathName(pathPtr, &volumePath[0], uint32(len(volumePath))); err != nil {
		return fmt.Errorf("application volume unavailable")
	}
	var serial uint32
	var fsName [windows.MAX_PATH]uint16
	if err = windows.GetVolumeInformation(&volumePath[0], nil, 0, &serial, nil, nil, &fsName[0], uint32(len(fsName))); err != nil || serial != appID.volume || !strings.EqualFold(windows.UTF16ToString(fsName[:]), "NTFS") {
		return fmt.Errorf("identity verification requires the qualified NTFS volume")
	}
	runtimeDir := filepath.Join(app, "runtime", pin.Architecture)
	locks, err := bootstraplock.LockProtectedTree(runtimeDir, parentPolicy)
	if err != nil {
		return fmt.Errorf("identity runtime is not protected")
	}
	defer locks.Close()
	executable := filepath.Join(runtimeDir, "node.exe")
	f, err := os.Open(executable)
	if err != nil {
		return fmt.Errorf("identity runtime unavailable")
	}
	defer f.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil || hex.EncodeToString(hash.Sum(nil)) != pin.NodeSHA256 {
		return fmt.Errorf("identity runtime does not match the independent pin")
	}
	winDir, err := windows.GetWindowsDirectory()
	if err != nil {
		return fmt.Errorf("Windows directory unavailable")
	}
	const probe = `const fs=require('fs'); const a=fs.statSync(process.env.TT_IDENTITY_APP,{bigint:true}); const b=fs.statSync(process.env.TT_IDENTITY_BACKUP,{bigint:true}); process.stdout.write(JSON.stringify({version:process.versions.node,arch:process.arch,app:a.dev.toString()+':'+a.ino.toString(),backup:b.dev.toString()+':'+b.ino.toString()}))`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "--no-addons", "-e", probe)
	cmd.Dir = runtimeDir
	cmd.Env = []string{"SystemRoot=" + winDir, "WINDIR=" + winDir, "TT_IDENTITY_APP=" + app, "TT_IDENTITY_BACKUP=" + previous}
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil || len(output) > 4096 {
		return fmt.Errorf("independent identity runtime failed")
	}
	var got struct {
		Version string `json:"version"`
		Arch    string `json:"arch"`
		App     string `json:"app"`
		Backup  string `json:"backup"`
	}
	if json.Unmarshal(output, &got) != nil {
		return fmt.Errorf("invalid independent identity result")
	}
	nodeArch := "x64"
	if pin.Architecture == "arm64" {
		nodeArch = "arm64"
	}
	native := func(id directoryIdentity) string {
		return fmt.Sprintf("%d:%d", id.volume, uint64(id.indexHigh)<<32|uint64(id.indexLow))
	}
	if got.Version != pin.NodeVersion || got.Arch != nodeArch || got.App != native(appID) || got.Backup != native(previousID) {
		return fmt.Errorf("Node and native identity observations do not match")
	}
	return nil
}
