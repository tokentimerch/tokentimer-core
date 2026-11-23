//go:build windows

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

const admissionEnv = "TOKENTIMER_AGENT_HOST_ADMISSION"
const admissionRequestBytes = 1 + 16
const admissionTimeout = 2 * time.Second

var admissionOperations = [...]string{
	"", "claim", "native", "cng-create", "ca-submit", "ca-retrieve", "store-accept", "store-cleanup",
}

type observedAdmission struct {
	observer serviceObservation
	failure  chan error
	onLoss   func()

	probeMu sync.Mutex
	stopped atomic.Bool
	lost    atomic.Bool
}

func (a *observedAdmission) revoke() {
	a.stopped.Store(true)
}

func (a *observedAdmission) fail(err error) {
	a.revoke()
	if a.lost.CompareAndSwap(false, true) {
		// The service handler must not see loss before the host has
		// attempted the Windows job fence and termination.
		a.onLoss()
		a.failure <- err
	}
}

func (a *observedAdmission) check() error {
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	if a.lost.Load() {
		return fmt.Errorf("observation revoked")
	}
	if err := a.observer.check(); err != nil {
		a.fail(err)
		return err
	}
	return nil
}

type admissionBroker struct {
	gate      *observedAdmission
	run       string
	listener  net.Listener
	journal   *os.File
	workerPID func() uint32
	key       [32]byte
	done      chan struct{}
	sequence  uint64 // One connection at a time.
}

// Keep the directory identity stable until the broker has drained and the
// journal is closed. This opt-in lab path requires a protected local root.
func openAdmissionJournal(configDir, run string) (_ *os.File, release func(), err error) {
	volume := filepath.VolumeName(configDir)
	if !validObservationRun(run) || !filepath.IsAbs(configDir) || len(volume) != 2 || volume[1] != ':' {
		return nil, nil, fmt.Errorf("a local observation state directory and valid run are required")
	}
	root, err := windows.UTF16PtrFromString(volume + "\\")
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return nil, nil, fmt.Errorf("observation state must reside on a fixed local drive")
	}
	trusted := map[string]bool{
		"S-1-5-18": true, "S-1-5-32-544": true,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
	}
	policy := bootstraplock.Policy{Owners: trusted, Writers: trusted}
	locks, err := bootstraplock.LockAncestors(configDir, policy)
	if err != nil {
		return nil, nil, fmt.Errorf("protect observation state directory: %w", err)
	}
	defer func() {
		if err != nil {
			locks.Close()
		}
	}()
	journalPath := filepath.Join(configDir, "observation-admission-"+run+".jsonl")
	name, err := windows.UTF16PtrFromString(journalPath)
	if err != nil {
		return nil, nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)")
	if err != nil {
		return nil, nil, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ,
		&attrs, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create exclusive admission journal: %w", err)
	}
	if err := policy.ValidateHandle(syscall.Handle(handle), false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, fmt.Errorf("verify admission journal ACL: %w", err)
	}
	file := os.NewFile(uintptr(handle), journalPath)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, fmt.Errorf("open admission journal handle")
	}
	return file, locks.Close, nil
}

func startAdmissionBroker(gate *observedAdmission, run string, journal *os.File, workerPID func() uint32) (*admissionBroker, error) {
	b := &admissionBroker{gate: gate, run: run, journal: journal, workerPID: workerPID, done: make(chan struct{})}
	if _, err := rand.Read(b.key[:]); err != nil {
		return nil, fmt.Errorf("generate observation admission capability: %w", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("open local admission listener: %w", err)
	}
	b.listener = listener
	go b.serve()
	return b, nil
}

func (b *admissionBroker) binding() string {
	return strconv.Itoa(b.listener.Addr().(*net.TCPAddr).Port) + ":" + hex.EncodeToString(b.key[:])
}

func (b *admissionBroker) close() {
	b.gate.revoke()
	_ = b.listener.Close()
	<-b.done
	clear(b.key[:])
}

func admissionMAC(key []byte, domain string, request []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, domain)
	_, _ = mac.Write(request)
	return mac.Sum(nil)
}

func (b *admissionBroker) serve() {
	defer close(b.done)
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			if !b.gate.stopped.Load() {
				b.gate.fail(fmt.Errorf("admission listener unavailable: %w", err))
			}
			return
		}
		b.handle(conn)
	}
}

func (b *admissionBroker) handle(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(admissionTimeout)); err != nil {
		return
	}
	var frame [admissionRequestBytes + sha256.Size]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		return
	}
	request := frame[:admissionRequestBytes]
	if !hmac.Equal(frame[admissionRequestBytes:], admissionMAC(b.key[:], "request", request)) {
		return
	}
	code := int(request[0])
	if code <= 0 || code >= len(admissionOperations) {
		return
	}
	decision := "eligible"
	if b.gate.stopped.Load() || b.gate.check() != nil || b.gate.stopped.Load() {
		decision = "denied"
	}
	if err := b.record(admissionOperations[code], decision, request[1:]); err != nil {
		b.gate.fail(fmt.Errorf("persist observation admission decision: %w", err))
		return
	}
	// A successful load is the local grant boundary. Stop and loss revoke
	// before this boundary, and no grant is cached. The worker can still be
	// descheduled between a grant and its effect; the record is not proof of
	// native launch or API acceptance.
	if decision != "eligible" || b.gate.stopped.Load() {
		return
	}
	_, _ = conn.Write(admissionMAC(b.key[:], "permit", request))
}

func (b *admissionBroker) record(operation, decision string, nonce []byte) error {
	pid := b.workerPID()
	if pid == 0 {
		return fmt.Errorf("observed worker identity is unavailable")
	}
	b.sequence++
	entry := struct {
		Run       string `json:"run"`
		HostPID   int    `json:"hostPid"`
		WorkerPID uint32 `json:"workerPid"`
		Sequence  uint64 `json:"sequence"`
		Operation string `json:"operation"`
		Decision  string `json:"decision"`
		Request   string `json:"request"`
		UTC       string `json:"utc"`
	}{b.run, os.Getpid(), pid, b.sequence, operation, decision, hex.EncodeToString(nonce), time.Now().UTC().Format(time.RFC3339Nano)}
	if err := json.NewEncoder(b.journal).Encode(entry); err != nil {
		return err
	}
	return b.journal.Sync()
}
