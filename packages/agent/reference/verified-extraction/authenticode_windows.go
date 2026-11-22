//go:build windows

package verifiedextraction

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

//go:embed verify-authenticode.ps1
var authenticodeVerifierScript string

type authenticodeFile struct {
	Path string `json:"path"`
	Pin  string `json:"pin"`
}

// verifyAuthenticode must run while the private extracted tree is locked.
// The vendor runtime pin and product publisher pin are independent inputs.
func verifyAuthenticode(root string, entries []Entry, architecture, publisherPin, runtimePin string) error {
	if architecture != "amd64" && architecture != "arm64" {
		return fmt.Errorf("unsupported architecture")
	}
	if !digest.MatchString(publisherPin) || !digest.MatchString(runtimePin) {
		return fmt.Errorf("invalid independent publisher pins")
	}
	var files []authenticodeFile
	hasInstaller, hasRuntime := false, false
	for _, e := range entries {
		name, err := canonical(e.Path, false)
		if err != nil {
			return err
		}
		lower := strings.ToLower(name)
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".cmd", ".bat", ".vbs", ".vbe", ".wsf", ".hta":
			return fmt.Errorf("unsupported Windows executable script type")
		}
		if ext != ".ps1" && ext != ".psm1" && ext != ".psd1" && ext != ".exe" {
			continue
		}
		pin := publisherPin
		if strings.HasPrefix(lower, "runtime/") && strings.HasSuffix(lower, "/node.exe") {
			if lower != "runtime/"+architecture+"/node.exe" || hasRuntime {
				return fmt.Errorf("wrong or duplicate runtime architecture")
			}
			pin = runtimePin
			hasRuntime = true
		}
		if lower == "scripts/install-agent.ps1" {
			hasInstaller = true
		}
		files = append(files, authenticodeFile{Path: filepath.Join(root, filepath.FromSlash(name)), Pin: pin})
	}
	if !hasInstaller || !hasRuntime {
		return fmt.Errorf("installer or Node runtime missing")
	}
	request, err := json.Marshal(struct {
		Files []authenticodeFile `json:"files"`
	}{files})
	if err != nil {
		return err
	}
	out, err := runSystemPowerShell(authenticodeVerifierScript, request)
	if err != nil || string(out) != "OK" {
		return fmt.Errorf("Authenticode publisher/timestamp verification failed")
	}
	return nil
}
