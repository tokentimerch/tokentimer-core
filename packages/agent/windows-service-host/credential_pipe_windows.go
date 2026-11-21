//go:build windows && credentialpipeexperiment

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const credentialPipeProofDomain = "TokenTimer-Credential-Pipe-Server-v1\x00"

// This experimental pipe is not wired into service startup or credential
// rotation. A live child PID plus OS handle cannot prevent deliberate handle
// duplication; actors at the same privilege level remain outside its boundary.
type credentialPipe struct {
	name   string
	handle windows.Handle
}

// credentialPipeSession owns a fresh CSPRNG capability for one host/child
// lifetime. It is not connected to service startup in experimental builds.
type credentialPipeSession struct {
	pipe *credentialPipe
	key  [32]byte
}

func newCredentialPipeSession(sddl string) (*credentialPipeSession, error) {
	p, err := newCredentialPipe(sddl)
	if err != nil {
		return nil, err
	}
	s := &credentialPipeSession{pipe: p}
	if _, err := rand.Read(s.key[:]); err != nil {
		p.Close()
		return nil, fmt.Errorf("pipe capability unavailable")
	}
	return s, nil
}

func (s *credentialPipeSession) Close() {
	if s.pipe != nil {
		s.pipe.Close()
		s.pipe = nil
	}
	clear(s.key[:])
}

func (s *credentialPipeSession) bootstrap() ([]byte, error) {
	if s == nil || s.pipe == nil {
		return nil, fmt.Errorf("pipe session unavailable")
	}
	return credentialPipeBootstrap(s.pipe.name, s.key[:])
}

func newCredentialPipe(sddl string) (*credentialPipe, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("pipe randomness unavailable")
	}
	name := `\\.\pipe\TokenTimerCredential-` + hex.EncodeToString(random)
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("invalid pipe name")
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("invalid pipe security")
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd, InheritHandle: 0}
	h, err := windows.CreateNamedPipe(ptr,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 4096, 4096, 0, &attrs)
	if err != nil {
		return nil, fmt.Errorf("pipe unavailable")
	}
	return &credentialPipe{name: name, handle: h}, nil
}

func (p *credentialPipe) Close() {
	if p.handle != 0 {
		_ = windows.CloseHandle(p.handle)
		p.handle = 0
	}
}

// accept waits for either a connection or the exact child process to exit.
// The supplied child handle must remain open for the duration of this call,
// preventing PID reuse from authenticating an unrelated process. Returns one
// connected handle only; caller owns it and must close it. No secret is logged.
func (p *credentialPipe) accept(child windows.Handle, timeoutMS uint32) (*os.File, error) {
	if p.handle == 0 || child == 0 || timeoutMS == 0 {
		return nil, fmt.Errorf("invalid pipe admission")
	}
	pid, err := windows.GetProcessId(child)
	if err != nil || pid == 0 {
		return nil, fmt.Errorf("child identity unavailable")
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("pipe event unavailable")
	}
	defer windows.CloseHandle(event)
	var ov windows.Overlapped
	ov.HEvent = event
	err = windows.ConnectNamedPipe(p.handle, &ov)
	if err == windows.ERROR_IO_PENDING {
		outcome, waitErr := windows.WaitForMultipleObjects([]windows.Handle{event, child}, false, timeoutMS)
		if waitErr != nil || outcome != windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(p.handle, &ov)
			_, _ = windows.WaitForSingleObject(event, windows.INFINITE)
			var ignored uint32
			_ = windows.GetOverlappedResult(p.handle, &ov, &ignored, false)
			return nil, fmt.Errorf("pipe connection unavailable")
		}
		var done uint32
		if err := windows.GetOverlappedResult(p.handle, &ov, &done, false); err != nil {
			return nil, fmt.Errorf("pipe connection failed")
		}
	} else if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return nil, fmt.Errorf("pipe connection failed")
	}
	// Verify liveness again even if connect and exit became signaled together.
	state, err := windows.WaitForSingleObject(child, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		return nil, fmt.Errorf("child exited")
	}
	var peer uint32
	if windows.GetNamedPipeClientProcessId(p.handle, &peer) != nil || peer != pid {
		return nil, fmt.Errorf("pipe peer rejected")
	}
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), p.handle, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, fmt.Errorf("pipe handle unavailable")
	}
	f := os.NewFile(uintptr(duplicate), "credential-ipc")
	if f == nil {
		_ = windows.CloseHandle(duplicate)
		return nil, fmt.Errorf("pipe unavailable")
	}
	return f, nil
}

// disconnect must only be called after the per-connection duplicate is closed.
// The original first-instance handle remains open so another process cannot
// claim the pipe name between requests. Not safe for concurrent calls.
func (p *credentialPipe) disconnect() error {
	if p.handle == 0 {
		return fmt.Errorf("pipe unavailable")
	}
	if err := windows.DisconnectNamedPipe(p.handle); err != nil {
		return fmt.Errorf("pipe disconnect failed")
	}
	return nil
}

// credentialPipeBootstrap is sent only over the specific child's inherited
// anonymous stdin, never argv/environment/logs. It is not an isolation boundary
// against a privileged actor able to inspect the child or duplicate its handles.
func credentialPipeBootstrap(name string, key []byte) ([]byte, error) {
	if len(name) == 0 || len(name) > 512 || len(key) != 32 {
		return nil, fmt.Errorf("invalid pipe bootstrap")
	}
	b := make([]byte, 2+len(name)+32)
	binary.BigEndian.PutUint16(b[:2], uint16(len(name)))
	copy(b[2:], name)
	copy(b[2+len(name):], key)
	return b, nil
}

// proveCredentialPipeServer must complete before receiving a credential.
// The peer supplies a fresh 32-byte challenge and checks the fixed-domain
// HMAC using the capability received through its private inherited stdin.
func proveCredentialPipeServer(f *os.File, key []byte, deadline time.Time) error {
	if f == nil || len(key) != 32 || deadline.IsZero() {
		return fmt.Errorf("invalid pipe proof")
	}
	if f.SetDeadline(deadline) != nil {
		return fmt.Errorf("pipe deadline unavailable")
	}
	var challenge [32]byte
	if _, err := io.ReadFull(f, challenge[:]); err != nil {
		return fmt.Errorf("pipe challenge unavailable")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(credentialPipeProofDomain))
	_, _ = mac.Write(challenge[:])
	proof := mac.Sum(nil)
	defer clear(proof)
	if n, err := f.Write(proof); err != nil || n != len(proof) {
		return fmt.Errorf("pipe proof unavailable")
	}
	return nil
}

// serveCredentialFrame accepts one bounded request and one bounded response.
// The handler must authenticate/validate its own command and must not log the
// request. This experimental framing is not yet wired to the agent or journal.
func serveCredentialFrame(f *os.File, deadline time.Time, handler func([]byte) ([]byte, error)) error {
	if f == nil || handler == nil || deadline.IsZero() {
		return fmt.Errorf("invalid pipe request")
	}
	if err := f.SetDeadline(deadline); err != nil {
		return fmt.Errorf("pipe deadline unavailable")
	}
	var header [4]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return fmt.Errorf("pipe request unavailable")
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > 1024 {
		return fmt.Errorf("invalid pipe request size")
	}
	request := make([]byte, size)
	defer clear(request)
	if _, err := io.ReadFull(f, request); err != nil {
		return fmt.Errorf("incomplete pipe request")
	}
	response, err := handler(request)
	if err != nil {
		return fmt.Errorf("pipe request rejected")
	}
	defer clear(response)
	if len(response) == 0 || len(response) > 1024 {
		return fmt.Errorf("invalid pipe response size")
	}
	binary.BigEndian.PutUint32(header[:], uint32(len(response)))
	if _, err := f.Write(header[:]); err != nil {
		return fmt.Errorf("pipe response unavailable")
	}
	if n, err := f.Write(response); err != nil || n != len(response) {
		return fmt.Errorf("pipe response unavailable")
	}
	return nil
}
