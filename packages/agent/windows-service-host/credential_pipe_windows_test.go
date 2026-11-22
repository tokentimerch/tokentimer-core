//go:build windows && credentialpipeexperiment

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCredentialPipeServerProof(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	peers := make(chan windows.Handle, 1)
	go func() { h, _ := openTestPipe(p.name); peers <- h }()
	server, err := p.accept(realCurrentProcess(t), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	h := <-peers
	if h == 0 {
		t.Fatal("client failed")
	}
	client := os.NewFile(uintptr(h), "pipe-test")
	defer client.Close()
	key := bytes.Repeat([]byte{7}, 32)
	challenge := bytes.Repeat([]byte{9}, 32)
	result := make(chan error, 1)
	go func() { result <- proveCredentialPipeServer(server, key, time.Now().Add(5*time.Second)) }()
	if _, err := client.Write(challenge); err != nil {
		t.Fatal(err)
	}
	proof := make([]byte, 32)
	if _, err := io.ReadFull(client, proof); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(credentialPipeProofDomain))
	_, _ = mac.Write(challenge)
	if !hmac.Equal(proof, mac.Sum(nil)) {
		t.Fatal("server proof mismatch")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestCredentialBootstrapChild(t *testing.T) {
	if os.Getenv("TT_BOOTSTRAP_CHILD") != "1" {
		return
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
	if err != nil {
		os.Exit(5)
	}
	hash := sha256.Sum256(b)
	_, _ = os.Stdout.Write([]byte(hex.EncodeToString(hash[:])))
	os.Exit(0)
}

func TestCredentialBootstrapGoesOnlyThroughChildStdin(t *testing.T) {
	key := bytes.Repeat([]byte{0x93}, 32)
	packet, err := credentialPipeBootstrap(`\\.\pipe\fixture`, key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestCredentialBootstrapChild$")
	child.Env = append(os.Environ(), "TT_BOOTSTRAP_CHILD=1")
	child.Stdin = reader
	var output bytes.Buffer
	child.Stdout = &output
	if err := child.Start(); err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	// A simultaneous process that was not given the read handle must see
	// only its own empty stdin, never the targeted child's capability.
	unrelated := exec.Command(exe, "-test.run=^TestCredentialBootstrapChild$")
	unrelated.Env = append(os.Environ(), "TT_BOOTSTRAP_CHILD=1")
	var otherOutput bytes.Buffer
	unrelated.Stdout = &otherOutput
	if err := unrelated.Run(); err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	emptyHash := sha256.Sum256(nil)
	if otherOutput.String() != hex.EncodeToString(emptyHash[:]) {
		reader.Close()
		writer.Close()
		t.Fatal("unrelated process received bootstrap")
	}
	_ = reader.Close()
	if _, err := writer.Write(packet); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	_ = writer.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(packet)
	if output.String() != hex.EncodeToString(want[:]) {
		t.Fatal("child did not receive exact packet")
	}
	if strings.Contains(strings.Join(child.Args, " "), hex.EncodeToString(key)) || strings.Contains(strings.Join(child.Env, " "), hex.EncodeToString(key)) {
		t.Fatal("capability exposed in args/environment")
	}
}

func TestCredentialPipeNodeGoInterop(t *testing.T) {
	node, err := exec.LookPath("node.exe")
	if err != nil {
		t.Skip("node.exe unavailable")
	}
	module, err := filepath.Abs(filepath.Join("..", "src", "protocol", "credential-pipe.js"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	key := bytes.Repeat([]byte{0x73}, 32)
	defer clear(key)
	packet, err := credentialPipeBootstrap(p.name, key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	script := `const c=require(process.argv[1]); (async()=>{const s=await c.receiveCredentialPipeBootstrap(process.stdin); const r=await c.sendCredentialPipeRequest(s,{command:'prepare',record:{version:1,operation:'a'.repeat(32),credential:'ttagent_'+'1'.repeat(16)+'_'+'2'.repeat(64)}}); s.dispose(); process.stdout.write(r.state);})().catch(()=>process.exit(1));`
	child := exec.Command(node, "-e", script, module)
	child.Stdin = reader
	var out bytes.Buffer
	child.Stdout = &out
	if err := child.Start(); err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	_ = reader.Close()
	defer child.Wait()
	if _, err := writer.Write(packet); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	_ = writer.Close()
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	conn, err := p.accept(process, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proveCredentialPipeServer(conn, key, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := serveCredentialFrame(conn, time.Now().Add(5*time.Second), func(request []byte) ([]byte, error) {
		if !bytes.Contains(request, []byte(`"command":"prepare"`)) {
			return nil, errors.New("wrong request")
		}
		return []byte(`{"state":"prepared"}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "prepared" {
		t.Fatal("node did not receive response")
	}
}

func pipeTestSDDL(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return "D:P(A;;GA;;;" + u.User.Sid.String() + ")"
}

func TestCredentialPipeSessionUsesFreshCapabilityAndClearsIt(t *testing.T) {
	a, err := newCredentialPipeSession(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := newCredentialPipeSession(pipeTestSDDL(t))
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	defer b.Close()
	if a.pipe.name == b.pipe.name || bytes.Equal(a.key[:], b.key[:]) {
		a.Close()
		t.Fatal("sessions reused identity or capability")
	}
	packet, err := a.bootstrap()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	if len(packet) < 32 || !bytes.Equal(packet[len(packet)-32:], a.key[:]) {
		a.Close()
		t.Fatal("incorrect bootstrap")
	}
	clear(packet)
	a.Close()
	if !bytes.Equal(a.key[:], make([]byte, 32)) {
		t.Fatal("capability not cleared")
	}
	if _, err := a.bootstrap(); err == nil {
		t.Fatal("closed session returned a bootstrap")
	}
}

func TestCredentialPipeFramesBoundedMessages(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	peer := make(chan windows.Handle, 1)
	go func() { h, _ := openTestPipe(p.name); peer <- h }()
	server, err := p.accept(realCurrentProcess(t), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	h := <-peer
	if h == 0 {
		t.Fatal("client failed")
	}
	client := os.NewFile(uintptr(h), "pipe-test")
	defer client.Close()
	result := make(chan error, 1)
	go func() {
		result <- serveCredentialFrame(server, time.Now().Add(5*time.Second), func(request []byte) ([]byte, error) {
			if string(request) != "fixture-secret" {
				return nil, errors.New("unexpected input")
			}
			return []byte("fixture-reply"), nil
		})
	}()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len("fixture-secret")))
	if _, err := client.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("fixture-secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, header[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(header[:])
	if n != uint32(len("fixture-reply")) {
		t.Fatal("wrong frame size")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(client, data); err != nil || string(data) != "fixture-reply" {
		t.Fatal("pipe reply mismatch")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestCredentialPipeRejectsOversizedFrame(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	peer := make(chan windows.Handle, 1)
	go func() { h, _ := openTestPipe(p.name); peer <- h }()
	server, err := p.accept(realCurrentProcess(t), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	h := <-peer
	if h == 0 {
		t.Fatal("client failed")
	}
	client := os.NewFile(uintptr(h), "pipe-test")
	defer client.Close()
	result := make(chan error, 1)
	go func() {
		result <- serveCredentialFrame(server, time.Now().Add(5*time.Second), func([]byte) ([]byte, error) { t.Error("oversized input reached handler"); return nil, nil })
	}()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 1025)
	if _, err := client.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("accepted oversized frame")
	}
}

func openTestPipe(name string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
}

func realCurrentProcess(t *testing.T) windows.Handle {
	t.Helper()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, windows.GetCurrentProcessId())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(h) })
	return h
}

func TestCredentialPipeAcceptsLiveExactProcess(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	clientResult := make(chan windows.Handle, 1)
	go func() { h, _ := openTestPipe(p.name); clientResult <- h }()
	f, err := p.accept(realCurrentProcess(t), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	client := <-clientResult
	if client == 0 {
		t.Fatal("client failed to connect")
	}
	defer windows.CloseHandle(client)
	var flags uint32
	getHandleInformation := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")
	r, _, _ := getHandleInformation.Call(uintptr(client), uintptr(unsafe.Pointer(&flags)))
	if r == 0 || flags&windows.HANDLE_FLAG_INHERIT != 0 {
		t.Fatal("client handle is inheritable")
	}
}

func TestCredentialPipeKeepsNameAcrossConnections(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	child := realCurrentProcess(t)
	for i := 0; i < 2; i++ {
		name, _ := windows.UTF16PtrFromString(p.name)
		if rogue, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 128, 128, 0, nil); err == nil {
			windows.CloseHandle(rogue)
			t.Fatal("pipe name could be claimed")
		}
		if rogue, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 128, 128, 0, nil); err == nil {
			windows.CloseHandle(rogue)
			t.Fatal("second pipe instance was allowed")
		}
		peers := make(chan windows.Handle, 1)
		go func() { h, _ := openTestPipe(p.name); peers <- h }()
		conn, err := p.accept(child, 5000)
		if err != nil {
			t.Fatal(err)
		}
		peer := <-peers
		if peer == 0 {
			conn.Close()
			t.Fatal("client failed")
		}
		_ = windows.CloseHandle(peer)
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if err := p.disconnect(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCredentialPipeTimesOutWithoutConnection(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	start := time.Now()
	if f, err := p.accept(realCurrentProcess(t), 100); err == nil {
		f.Close()
		t.Fatal("accepted without connection")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("pipe wait was not bounded")
	}
}

func TestCredentialPipeReadDeadline(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	clientResult := make(chan windows.Handle, 1)
	go func() { h, _ := openTestPipe(p.name); clientResult <- h }()
	f, err := p.accept(realCurrentProcess(t), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	client := <-clientResult
	if client == 0 {
		t.Fatal("client failed to connect")
	}
	defer windows.CloseHandle(client)
	if err := f.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("deadline unavailable: %v", err)
	}
	start := time.Now()
	var b [1]byte
	if _, err := f.Read(b[:]); err == nil {
		t.Fatal("unexpected data")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("read deadline did not bound the wait")
	}
}

func TestCredentialPipeConnectChild(t *testing.T) {
	name := os.Getenv("TT_CREDENTIAL_PIPE_TEST")
	if name == "" {
		return
	}
	h, err := openTestPipe(name)
	if err != nil {
		os.Exit(4)
	}
	defer windows.CloseHandle(h)
	time.Sleep(500 * time.Millisecond)
}

func TestCredentialPipeRejectsDifferentProcess(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestCredentialPipeConnectChild$")
	child.Env = append(os.Environ(), "TT_CREDENTIAL_PIPE_TEST="+p.name)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Wait()
	if f, err := p.accept(realCurrentProcess(t), 5000); err == nil {
		f.Close()
		t.Fatal("accepted unrelated process")
	} else if err.Error() != "pipe peer rejected" {
		t.Fatalf("did not observe peer rejection: %v", err)
	}
}

func TestCredentialPipeExitChild(t *testing.T) {
	if os.Getenv("TT_CREDENTIAL_PIPE_EXIT_CHILD") != "1" {
		return
	}
	time.Sleep(200 * time.Millisecond)
}

func TestCredentialPipeStopsWhenExpectedChildExits(t *testing.T) {
	p, err := newCredentialPipe(pipeTestSDDL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestCredentialPipeExitChild$")
	child.Env = append(os.Environ(), "TT_CREDENTIAL_PIPE_EXIT_CHILD=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Wait()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	start := time.Now()
	if f, err := p.accept(h, 5000); err == nil {
		f.Close()
		t.Fatal("accepted exited child")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not stop after child exited")
	}
}
