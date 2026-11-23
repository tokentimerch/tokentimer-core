//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const observationRunEnv = "TOKENTIMER_AGENT_HOST_OBSERVATION_RUN"
const observationInterval = time.Second
const observationReplyTimeout = 500 * time.Millisecond

type serviceObservation interface {
	check() error
	reserve() error
	close()
}

var flushObservationRun = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegFlushKey")

type observationPipe struct {
	pipe *os.File
	peer windows.Handle
	run  string
}

func validObservationRun(run string) bool {
	decoded, err := hex.DecodeString(run)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == run
}

func connectObservation(run string) (serviceObservation, error) {
	if !validObservationRun(run) {
		return nil, fmt.Errorf("observation run must be 32 lowercase hexadecimal characters")
	}
	name, err := windows.UTF16PtrFromString(observationPipeName(run))
	if err != nil {
		return nil, fmt.Errorf("invalid observation pipe name")
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return nil, fmt.Errorf("open local observation pipe: %w", err)
	}
	peer, err := openObservationPeer(handle)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	pipe := os.NewFile(uintptr(handle), "service-observation")
	if pipe == nil {
		_ = windows.CloseHandle(handle)
		_ = windows.CloseHandle(peer)
		return nil, fmt.Errorf("observation pipe unavailable")
	}
	return &observationPipe{pipe: pipe, peer: peer, run: run}, nil
}

func observationPipeName(run string) string {
	return "\\\\.\\pipe\\TokenTimerObservation-" + run
}

func openObservationPeer(pipe windows.Handle) (windows.Handle, error) {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil || pid == 0 || pid == uint32(os.Getpid()) {
		return 0, fmt.Errorf("independent observation pipe peer required")
	}
	peer, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return 0, fmt.Errorf("open observation peer: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = windows.CloseHandle(peer)
		}
	}()
	var token windows.Token
	if err := windows.OpenProcessToken(peer, windows.TOKEN_QUERY, &token); err != nil {
		return 0, fmt.Errorf("open observation peer token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return 0, fmt.Errorf("observation pipe peer must be LocalSystem")
	}
	var confirmed uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &confirmed); err != nil || confirmed != pid || !observationPeerAlive(peer) {
		return 0, fmt.Errorf("observation peer identity changed")
	}
	ok = true
	return peer, nil
}

func observationPeerAlive(peer windows.Handle) bool {
	state, err := windows.WaitForSingleObject(peer, 0)
	return err == nil && state == uint32(windows.WAIT_TIMEOUT)
}

func (o *observationPipe) check() error {
	if !observationPeerAlive(o.peer) {
		return fmt.Errorf("observation peer exited")
	}
	if err := verifyObservationReply(o.pipe); err != nil {
		return err
	}
	if !observationPeerAlive(o.peer) {
		return fmt.Errorf("observation peer exited")
	}
	return nil
}

type observationStream interface {
	io.ReadWriter
	SetDeadline(time.Time) error
}

// Only the independently qualified collector can attest CA and CNG coverage.
// A fresh challenge proves a reply on this connection, not coverage by itself.
func verifyObservationReply(stream observationStream) error {
	if err := stream.SetDeadline(time.Now().Add(observationReplyTimeout)); err != nil {
		return fmt.Errorf("observation deadline unavailable")
	}
	var challenge, reply [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return fmt.Errorf("observation challenge unavailable")
	}
	if n, err := stream.Write(challenge[:]); err != nil || n != len(challenge) {
		return fmt.Errorf("observation challenge delivery failed")
	}
	if _, err := io.ReadFull(stream, reply[:]); err != nil || reply != challenge {
		return fmt.Errorf("fresh observation reply missing")
	}
	return nil
}

// Reserve the run once before starting the worker. A service crash or SCM
// retry must not reuse an admitted run, even if the same peer is still alive.
func (o *observationPipe) reserve() error {
	path := "SYSTEM\\CurrentControlSet\\Services\\" + serviceName + "\\ObservationRuns\\" + o.run
	key, existed, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("reserve observation run: %w", err)
	}
	defer key.Close()
	if existed {
		return fmt.Errorf("observation run already used; a new run is required")
	}
	status, _, _ := flushObservationRun.Call(uintptr(key))
	if status != 0 {
		return fmt.Errorf("persist observation run: %w", syscall.Errno(status))
	}
	return nil
}

func (o *observationPipe) close() {
	_ = o.pipe.Close()
	_ = windows.CloseHandle(o.peer)
}
