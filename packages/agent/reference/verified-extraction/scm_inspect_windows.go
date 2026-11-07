//go:build windows

package verifiedextraction

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceRecoveryInspection reports the current configuration, never the SCM
// action queue. In particular, an empty list does not authorize cleanup.
type ServiceRecoveryInspection struct {
	Service           string                  `json:"service"`
	ConfiguredActions []ServiceRecoveryAction `json:"configuredActions"`
	NonCrashFailures  *bool                   `json:"nonCrashFailures"`
	Notice            string                  `json:"notice"`
}
type ServiceRecoveryAction struct {
	Type              string `json:"type"`
	DelayMilliseconds int64  `json:"delayMilliseconds"`
}

func recoveryActionName(kind int) string {
	switch kind {
	case mgr.NoAction:
		return "none"
	case mgr.ServiceRestart:
		return "restart-service"
	case mgr.ComputerReboot:
		return "reboot"
	case mgr.RunCommand:
		return "run-command"
	default:
		return "unknown"
	}
}

func InspectServiceRecovery() (ServiceRecoveryInspection, error) {
	return inspectServiceRecovery("TokenTimerAgent")
}

func inspectServiceRecovery(name string) (ServiceRecoveryInspection, error) {
	result := ServiceRecoveryInspection{ConfiguredActions: []ServiceRecoveryAction{}, Notice: "Current configuration only; queued SCM actions and WMI activity are not observable here. Preserve quarantined files and contact support."}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return result, fmt.Errorf("service control manager unavailable")
	}
	defer windows.CloseServiceHandle(manager)
	serviceName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return result, fmt.Errorf("invalid service name")
	}
	h, err := windows.OpenService(manager, serviceName, windows.SERVICE_QUERY_CONFIG)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		result.Service = "absent"
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("service configuration unavailable")
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()
	result.Service = "present"
	actions, err := s.RecoveryActions()
	if err != nil {
		return ServiceRecoveryInspection{}, fmt.Errorf("service failure actions unavailable")
	}
	for _, action := range actions {
		result.ConfiguredActions = append(result.ConfiguredActions, ServiceRecoveryAction{Type: recoveryActionName(action.Type), DelayMilliseconds: int64(action.Delay / time.Millisecond)})
	}
	nonCrash, err := s.RecoveryActionsOnNonCrashFailures()
	if err != nil {
		return ServiceRecoveryInspection{}, fmt.Errorf("service failure flag unavailable")
	}
	result.NonCrashFailures = &nonCrash
	return result, nil
}
