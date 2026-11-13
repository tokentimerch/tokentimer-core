//go:build windows

package verifiedextraction

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var experimentalCrypt32 = windows.NewLazySystemDLL("crypt32.dll")
var experimentalVerifyTimestamp = experimentalCrypt32.NewProc("CryptVerifyTimeStampSignature")
var experimentalCryptMemFree = experimentalCrypt32.NewProc("CryptMemFree")

type experimentalBlob struct {
	size uint32
	data *byte
}
type experimentalAlgorithm struct {
	oid        *byte
	parameters experimentalBlob
}
type experimentalTimestampInfo struct {
	version   uint32
	policy    *byte
	algorithm experimentalAlgorithm
	hash      experimentalBlob
	serial    experimentalBlob
	time      windows.Filetime
}
type experimentalTimestampContext struct {
	size    uint32
	encoded *byte
	info    *experimentalTimestampInfo
}

// verifyExperimentalTimestamp proves only the timestamp signature and its
// binding to the CMS signature; the caller must also validate both chains.
func verifyExperimentalTimestamp(token, signature []byte) (time.Time, []byte, error) {
	if len(token) == 0 || len(token) > 8<<20 || len(signature) == 0 || len(signature) > 64<<10 {
		return time.Time{}, nil, fmt.Errorf("invalid timestamp inputs")
	}
	var context *experimentalTimestampContext
	var signer *windows.CertContext
	var store windows.Handle
	result, _, callErr := experimentalVerifyTimestamp.Call(
		uintptr(unsafe.Pointer(&token[0])), uintptr(len(token)),
		uintptr(unsafe.Pointer(&signature[0])), uintptr(len(signature)), 0,
		uintptr(unsafe.Pointer(&context)), uintptr(unsafe.Pointer(&signer)), uintptr(unsafe.Pointer(&store)),
	)
	runtime.KeepAlive(token)
	runtime.KeepAlive(signature)
	if context != nil {
		defer experimentalCryptMemFree.Call(uintptr(unsafe.Pointer(context)))
	}
	if signer != nil {
		defer windows.CertFreeCertificateContext(signer)
	}
	if store != 0 {
		defer windows.CertCloseStore(store, 0)
	}
	if result == 0 {
		return time.Time{}, nil, fmt.Errorf("timestamp signature invalid: %w", callErr)
	}
	if context == nil || context.info == nil || signer == nil || signer.EncodedCert == nil || signer.Length == 0 || signer.Length > 1<<20 || context.info.algorithm.oid == nil {
		return time.Time{}, nil, fmt.Errorf("incomplete timestamp result")
	}
	if windows.BytePtrToString(context.info.algorithm.oid) != "2.16.840.1.101.3.4.2.1" {
		return time.Time{}, nil, fmt.Errorf("invalid timestamp digest")
	}
	// Filetime.Nanoseconds can overflow for extreme native FILETIME values.
	// Bound the source before converting it to a Go time.
	filetime := uint64(context.info.time.HighDateTime)<<32 | uint64(context.info.time.LowDateTime)
	min := windows.NsecToFiletime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	max := windows.NsecToFiletime(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	if filetime < uint64(min.HighDateTime)<<32|uint64(min.LowDateTime) || filetime > uint64(max.HighDateTime)<<32|uint64(max.LowDateTime) {
		return time.Time{}, nil, fmt.Errorf("timestamp outside supported range")
	}
	cert := append([]byte(nil), unsafe.Slice(signer.EncodedCert, int(signer.Length))...)
	stamp := time.Unix(0, context.info.time.Nanoseconds()).UTC()
	if stamp.After(time.Now().UTC().Add(5 * time.Minute)) {
		return time.Time{}, nil, fmt.Errorf("timestamp is in the future")
	}
	return stamp, cert, nil
}
