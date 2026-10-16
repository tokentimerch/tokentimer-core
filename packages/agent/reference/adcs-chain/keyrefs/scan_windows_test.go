//go:build windows

package keyrefs

import (
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"unsafe"
)

func TestBoundedProviderStrings(t *testing.T) {
	chars, _ := windows.UTF16FromString("owned")
	data := make([]byte, len(chars)*2)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&data[0])), len(chars)), chars)
	if s, ok := pointerString((*uint16)(unsafe.Pointer(&data[0])), data); !ok || s != "owned" {
		t.Fatal("valid bounded string refused")
	}
	if _, ok := pointerString(nil, data); ok {
		t.Fatal("nil accepted")
	}
	foreign, _ := windows.UTF16PtrFromString("foreign")
	if _, ok := pointerString(foreign, data); ok {
		t.Fatal("pointer outside property buffer accepted")
	}
	data[len(data)-2] = 1
	if _, ok := pointerString((*uint16)(unsafe.Pointer(&data[0])), data); ok {
		t.Fatal("unterminated accepted")
	}
}

// Actual read-only metadata enumeration: no certificate/key changes or private
// operations. Supporting runs may prove safe refusal on restricted hosts; strict
// native qualification requires a complete inventory, never an incomplete pass.
func TestNativeMetadataScanReadOnlySupportingOrStrictQualification(t *testing.T) {
	r := Scan(Request{"tokentimer-readonly-no-such-container-7bc2", "My", "0000000000000000000000000000000000000000"})
	if !r.Complete {
		if os.Getenv("CERTOPS_QUALIFICATION_STRICT") == "1" {
			t.Fatalf("strict native inventory incomplete: %s", r.Reason)
		}
		if !r.Shared || r.Reason == "" {
			t.Fatal("incomplete scan not unsafe")
		}
		t.Logf("read-only native enumeration safely refused: %s", r.Reason)
		return
	}
	if r.Shared || r.Matches != 0 || r.StoresScanned < 1 {
		t.Fatal("unexpected nonexistent-container reference")
	}
	t.Logf("read-only native metadata scan complete: stores=%d certificates=%d", r.StoresScanned, r.CertificatesScanned)
}
