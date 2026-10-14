//go:build windows

// Metadata-only Crypt32 enumeration includes archived certificate contexts and
// custom LocalMachine logical stores. CERT_KEY_PROV_INFO does not open a key.
package keyrefs

import (
	"crypto/sha1"
	"encoding/hex"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

var crypt = windows.NewLazySystemDLL("crypt32.dll")
var enumStores = crypt.NewProc("CertEnumSystemStore")
var openStore = crypt.NewProc("CertOpenStore")
var closeStore = crypt.NewProc("CertCloseStore")
var getProperty = crypt.NewProc("CertGetCertificateContextProperty")

type providerInfo struct {
	Container *uint16
	Provider  *uint16
	ProvType  uint32
	Flags     uint32
	Count     uint32
	Params    uintptr
	KeySpec   uint32
}

const notFound = 0x80092004

func pointerString(p *uint16, buffer []byte) (string, bool) {
	if p == nil {
		return "", false
	}
	base := uintptr(unsafe.Pointer(&buffer[0]))
	addr := uintptr(unsafe.Pointer(p))
	end := base + uintptr(len(buffer))
	if addr < base || addr >= end || addr%2 != 0 {
		return "", false
	}
	max := (end - addr) / 2
	if max > 2048 {
		max = 2048
	}
	chars := unsafe.Slice(p, int(max))
	for i, v := range chars {
		if v == 0 {
			return windows.UTF16ToString(chars[:i]), true
		}
	}
	return "", false
}
func Scan(r Request) Result {
	out := Result{}
	if !r.Valid() {
		return incomplete("invalid_request", out)
	}
	names := []string{}
	bad := false
	callback := windows.NewCallback(func(name *uint16, flags, info, arg, reserved uintptr) uintptr {
		if name == nil || flags != 0x20000 || len(names) >= MaxStores {
			bad = true
			return 0
		}
		s := windows.UTF16PtrToString(name)
		if len(s) == 0 || len(s) > 256 {
			bad = true
			return 0
		}
		names = append(names, s)
		return 1
	})
	ok, _, _ := enumStores.Call(0x20000, 0, 0, callback)
	if ok == 0 || bad || len(names) == 0 {
		return incomplete("store_enumeration_failed", out)
	}
	for _, name := range names {
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return incomplete("store_name_invalid", out)
		}
		// SYSTEM_W, LOCAL_MACHINE | READONLY | OPEN_EXISTING | ENUM_ARCHIVED.
		store, _, _ := openStore.Call(10, 0, 0, 0x20000|0x8000|0x4000|0x200, uintptr(unsafe.Pointer(namePtr)))
		if store == 0 {
			return incomplete("store_open_failed", out)
		}
		out.StoresScanned++
		var previous *windows.CertContext
		failed := ""
		for {
			current, last := windows.CertEnumCertificatesInStore(windows.Handle(store), previous)
			previous = current
			if current == nil {
				if last != windows.Errno(notFound) {
					failed = "certificate_enumeration_failed"
				}
				break
			}
			if out.CertificatesScanned >= MaxCertificates {
				failed = "certificate_limit"
				break
			}
			out.CertificatesScanned++
			c := current
			if c.EncodedCert == nil || c.Length == 0 || c.Length > 1048576 {
				failed = "certificate_context_invalid"
				break
			}
			var size uint32
			found, _, last := getProperty.Call(uintptr(unsafe.Pointer(current)), 2, 0, uintptr(unsafe.Pointer(&size)))
			if found == 0 {
				if last == windows.Errno(notFound) {
					continue
				}
				failed = "provider_metadata_failed"
				break
			}
			if size < uint32(unsafe.Sizeof(providerInfo{})) || size > 65536 {
				failed = "provider_metadata_invalid"
				break
			}
			data := make([]byte, size)
			found, _, _ = getProperty.Call(uintptr(unsafe.Pointer(current)), 2, uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)))
			if found == 0 || int(size) > len(data) || size < uint32(unsafe.Sizeof(providerInfo{})) {
				failed = "provider_metadata_failed"
				break
			}
			data = data[:size]
			p := (*providerInfo)(unsafe.Pointer(&data[0]))
			// A legacy CSP cannot refer to this CNG KSP. Its optional provider/
			// container pointers need not be populated and no key is opened.
			if p.ProvType != 0 {
				continue
			}
			provider, validProvider := pointerString(p.Provider, data)
			if !validProvider {
				failed = "provider_metadata_invalid"
				break
			}
			if !strings.EqualFold(provider, SoftwareKSP) || p.Flags&0x20 == 0 {
				continue
			}
			container, validContainer := pointerString(p.Container, data)
			if !validContainer {
				failed = "provider_metadata_invalid"
				break
			}
			digest := sha1.Sum(unsafe.Slice(c.EncodedCert, int(c.Length)))
			thumb := strings.ToUpper(hex.EncodeToString(digest[:]))
			if survivor(r, name, thumb, container, provider, p.Flags&0x20 != 0, p.ProvType) {
				out.Matches++
			}
		}
		if previous != nil {
			windows.CertFreeCertificateContext(previous)
		}
		closed, _, _ := closeStore.Call(store, 0)
		if closed == 0 && failed == "" {
			failed = "store_close_failed"
		}
		if failed != "" {
			return incomplete(failed, out)
		}
	}
	out.Complete = true
	out.Shared = out.Matches > 0
	return out
}
