//go:build windows

package verifiedextraction

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// EXPERIMENT ONLY. WinTrust provider helper structs are Windows-version
// dependent, and RFC3161/legacy timestamps and revocation behavior require
// independent native qualification. This function is not used by the launcher.
type providerSignerPrefix struct {
	Size         uint32
	VerifyAsOf   windows.Filetime
	CertCount    uint32
	CertChain    uintptr
	SignerType   uint32
	SignerInfo   *nativeCMSSignerInfo
	Error        uint32
	CounterCount uint32
	Counters     uintptr
	Chain        *windows.CertChainContext
}
type providerCertPrefix struct {
	Size        uint32
	Certificate *windows.CertContext
}

type nativeCryptAttribute struct {
	OID        *byte
	ValueCount uint32
	Values     *windows.CryptAttrBlob
}
type nativeCryptAttributes struct {
	Count      uint32
	Attributes *nativeCryptAttribute
}
type nativeCMSSignerInfo struct {
	Version                 uint32
	Issuer                  windows.CertNameBlob
	Serial                  windows.CryptIntegerBlob
	HashAlgorithm           windows.CryptAlgorithmIdentifier
	HashEncryptionAlgorithm windows.CryptAlgorithmIdentifier
	EncryptedHash           windows.CryptDataBlob
	Authenticated           nativeCryptAttributes
	Unauthenticated         nativeCryptAttributes
}

func hasSingleRFC3161Timestamp(info *nativeCMSSignerInfo) bool {
	if info == nil || info.HashAlgorithm.ObjId == nil || windows.BytePtrToString(info.HashAlgorithm.ObjId) != "2.16.840.1.101.3.4.2.1" || info.Unauthenticated.Count == 0 || info.Unauthenticated.Count > 64 || info.Unauthenticated.Attributes == nil {
		return false
	}
	matches := 0
	for _, attr := range unsafe.Slice(info.Unauthenticated.Attributes, int(info.Unauthenticated.Count)) {
		if attr.OID == nil {
			return false
		}
		oid := windows.BytePtrToString(attr.OID)
		// Reject legacy countersignatures rather than accepting an unrelated
		// RFC3161 attribute alongside the actually verified timestamp.
		if oid == "1.2.840.113549.1.9.6" {
			return false
		}
		if oid == "1.3.6.1.4.1.311.3.3.1" {
			if attr.ValueCount != 1 || attr.Values == nil || attr.Values.Size == 0 || attr.Values.Data == nil {
				return false
			}
			matches++
		}
	}
	return matches == 1
}

func nativeAuthenticodePrototype(path, pin string) error {
	if !filepath.IsAbs(path) || !digest.MatchString(pin) {
		return fmt.Errorf("invalid verifier input")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	f, err := lockSignedFile(name)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := experimentalSpcSHA256(f); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	file := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: name, File: windows.Handle(f.Fd())}
	settings := windows.WinTrustSignatureSettings{Size: uint32(unsafe.Sizeof(windows.WinTrustSignatureSettings{})), Index: 0, Flags: 0x1 | 0x2}
	data := windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN, UnionChoice: windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file), StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags:         windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | windows.WTD_DISABLE_MD2_MD4,
		SignatureSettings: &settings,
	}
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	}()
	if err != nil {
		return fmt.Errorf("Windows trust verification: %w", err)
	}
	if settings.VerifiedSigIndex != 0 || settings.SecondarySigs != 0 {
		return fmt.Errorf("ambiguous Authenticode signature set")
	}
	dll := windows.NewLazySystemDLL("wintrust.dll")
	prov := dll.NewProc("WTHelperProvDataFromStateData")
	signerProc := dll.NewProc("WTHelperGetProvSignerFromChain")
	certProc := dll.NewProc("WTHelperGetProvCertFromChain")
	for _, p := range []*windows.LazyProc{prov, signerProc, certProc} {
		if err := p.Find(); err != nil {
			return fmt.Errorf("trust provider helper unavailable")
		}
	}
	provider, _, _ := prov.Call(uintptr(data.StateData))
	if provider == 0 {
		return fmt.Errorf("trust provider data unavailable")
	}
	signerPtr, _, _ := signerProc.Call(provider, 0, 0, 0)
	if signerPtr == 0 {
		return fmt.Errorf("signer unavailable")
	}
	signer := (*providerSignerPrefix)(nativeTrustPointer(signerPtr))
	if signer.Size < uint32(unsafe.Sizeof(providerSignerPrefix{})) {
		return fmt.Errorf("unsupported publisher provider structure")
	}
	if signer.Error != 0 || signer.CertCount == 0 || signer.CounterCount != 1 || signer.Chain == nil || !hasSingleRFC3161Timestamp(signer.SignerInfo) {
		return fmt.Errorf("publisher or timestamp unavailable")
	}
	if signer.Chain.Size < uint32(unsafe.Offsetof(windows.CertChainContext{}.TrustStatus)+unsafe.Sizeof(windows.CertTrustStatus{})) {
		return fmt.Errorf("unsupported publisher chain structure")
	}
	if signer.Chain.TrustStatus.ErrorStatus != 0 {
		return fmt.Errorf("publisher chain trust status: 0x%08x", signer.Chain.TrustStatus.ErrorStatus)
	}
	certPtr, _, _ := certProc.Call(signerPtr, 0)
	if certPtr == 0 {
		return fmt.Errorf("publisher certificate unavailable")
	}
	providerCert := (*providerCertPrefix)(nativeTrustPointer(certPtr))
	if providerCert.Size < uint32(unsafe.Sizeof(providerCertPrefix{})) {
		return fmt.Errorf("unsupported publisher certificate structure")
	}
	cert := providerCert.Certificate
	if cert == nil || cert.EncodedCert == nil || cert.Length == 0 || cert.Length > 1<<20 {
		return fmt.Errorf("invalid publisher certificate")
	}
	if !nativeCertificateMatchesPin(unsafe.Slice(cert.EncodedCert, int(cert.Length)), pin) {
		return fmt.Errorf("publisher mismatch")
	}
	counterPtr, _, _ := signerProc.Call(provider, 0, 1, 0)
	if counterPtr == 0 {
		return fmt.Errorf("timestamp signer unavailable")
	}
	counter := (*providerSignerPrefix)(nativeTrustPointer(counterPtr))
	if counter.Size < uint32(unsafe.Sizeof(providerSignerPrefix{})) {
		return fmt.Errorf("unsupported timestamp provider structure")
	}
	if counter.Error != 0 || counter.SignerType != 0x10 || counter.CertCount == 0 || counter.Chain == nil || (counter.VerifyAsOf.HighDateTime == 0 && counter.VerifyAsOf.LowDateTime == 0) {
		return fmt.Errorf("timestamp verification unavailable")
	}
	if counter.Chain.Size < uint32(unsafe.Offsetof(windows.CertChainContext{}.TrustStatus)+unsafe.Sizeof(windows.CertTrustStatus{})) {
		return fmt.Errorf("unsupported timestamp chain structure")
	}
	if counter.Chain.TrustStatus.ErrorStatus != 0 {
		return fmt.Errorf("timestamp chain trust status: 0x%08x", counter.Chain.TrustStatus.ErrorStatus)
	}
	counterCertPtr, _, _ := certProc.Call(counterPtr, 0)
	if counterCertPtr == 0 {
		return fmt.Errorf("timestamp certificate unavailable")
	}
	timestampProviderCert := (*providerCertPrefix)(nativeTrustPointer(counterCertPtr))
	if timestampProviderCert.Size < uint32(unsafe.Sizeof(providerCertPrefix{})) {
		return fmt.Errorf("unsupported timestamp certificate structure")
	}
	counterCert := timestampProviderCert.Certificate
	if counterCert == nil || counterCert.EncodedCert == nil || counterCert.Length == 0 || counterCert.Length > 1<<20 {
		return fmt.Errorf("invalid timestamp certificate")
	}
	parsed, err := x509.ParseCertificate(unsafe.Slice(counterCert.EncodedCert, int(counterCert.Length)))
	if err != nil {
		return fmt.Errorf("invalid timestamp certificate")
	}
	allowed := false
	for _, usage := range parsed.ExtKeyUsage {
		if usage == x509.ExtKeyUsageTimeStamping {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("timestamp signing usage missing")
	}
	return nil
}

func lockSignedFile(name *uint16) (*os.File, error) {
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("lock signed file: %w", err)
	}
	f := os.NewFile(uintptr(h), "locked-signed-file")
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("locked signed file unavailable")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		f.Close()
		return nil, fmt.Errorf("invalid signed file identity")
	}
	return f, nil
}

// Native WinTrust returns an unmanaged pointer, valid until its state is
// closed. The caller keeps that state open for the complete read.
//
//go:nocheckptr
func nativeTrustPointer(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) }

func nativeCertificateMatchesPin(der []byte, pin string) bool {
	if len(der) == 0 || !digest.MatchString(pin) {
		return false
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]) == pin
}
