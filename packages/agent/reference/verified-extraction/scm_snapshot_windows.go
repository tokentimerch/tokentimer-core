//go:build windows

package verifiedextraction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// This diagnostic digest is never used to authorize recovery and is not a
// substitute for the protected installer rollback record.
func currentSCMDigest() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	s, err := m.OpenService("TokenTimerAgent")
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return digestSCMValue(struct{ Absent bool }{true})
	}
	if err != nil {
		return "", err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return "", err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\TokenTimerAgent`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()
	env, _, err := key.GetStringsValue("Environment")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return "", err
	}
	return digestSCMValue(struct {
		Config      mgr.Config
		Environment []string
	}{cfg, env})
}

func digestSCMValue(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("service snapshot: %w", err)
	}
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:]), nil
}
