//go:build windows

package verifiedextraction

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Experimental, not wired to the launcher. Independent Windows review and
// trusted/revoked/offline fixtures are required before use in any release.
type cryptVerifyMessagePara struct {
	Size                 uint32
	Encoding             uint32
	CryptProvider        uintptr
	GetSignerCertificate uintptr
	GetArgument          uintptr
}

func takeDER(in []byte) (asn1.RawValue, []byte, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(in, &v)
	if err != nil {
		return v, nil, err
	}
	return v, rest, nil
}
func onlyDER(in []byte) (asn1.RawValue, error) {
	v, rest, err := takeDER(in)
	if err != nil || len(rest) != 0 {
		return v, fmt.Errorf("invalid DER")
	}
	return v, nil
}
func isDER(v asn1.RawValue, class, tag int, compound bool) bool {
	return v.Class == class && v.Tag == tag && v.IsCompound == compound
}
func requireOID(in []byte, expected asn1.ObjectIdentifier) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(in, &oid)
	if err != nil || !oid.Equal(expected) {
		return nil, fmt.Errorf("unexpected CMS algorithm")
	}
	return rest, nil
}

func requireSHA256Algorithm(algorithm asn1.RawValue) error {
	if !isDER(algorithm, 0, 16, true) {
		return fmt.Errorf("invalid digest algorithm")
	}
	rest, err := requireOID(algorithm.Bytes, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return nil
	}
	parameter, err := onlyDER(rest)
	if err != nil || !isDER(parameter, 0, 5, false) || len(parameter.Bytes) != 0 {
		return fmt.Errorf("invalid digest parameters")
	}
	return nil
}

// cmsShape enforces a single SHA-256 SignerInfo and embedded data. This parser
// deliberately rejects non-DER encodings, unknown outer fields and detached
// content; it does not itself verify a signature.
func cmsShape(cms []byte) error {
	if len(cms) == 0 || len(cms) > 8<<20 {
		return fmt.Errorf("invalid CMS size")
	}
	outer, err := onlyDER(cms)
	if err != nil || !isDER(outer, 0, 16, true) {
		return fmt.Errorf("invalid CMS outer sequence")
	}
	rest, err := requireOID(outer.Bytes, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})
	if err != nil {
		return err
	}
	explicit, err := onlyDER(rest)
	if err != nil || !isDER(explicit, 2, 0, true) {
		return fmt.Errorf("invalid CMS signed wrapper")
	}
	signed, err := onlyDER(explicit.Bytes)
	if err != nil || !isDER(signed, 0, 16, true) {
		return fmt.Errorf("invalid CMS signed data")
	}
	version, rest, err := takeDER(signed.Bytes)
	if err != nil || !isDER(version, 0, 2, false) {
		return fmt.Errorf("invalid CMS version")
	}
	algorithms, rest, err := takeDER(rest)
	if err != nil || !isDER(algorithms, 0, 17, true) {
		return fmt.Errorf("invalid CMS digest set")
	}
	alg, err := onlyDER(algorithms.Bytes)
	if err != nil || !isDER(alg, 0, 16, true) {
		return fmt.Errorf("ambiguous CMS digest set")
	}
	if err := requireSHA256Algorithm(alg); err != nil {
		return err
	}
	content, rest, err := takeDER(rest)
	if err != nil || !isDER(content, 0, 16, true) {
		return fmt.Errorf("invalid CMS content")
	}
	contentRest, err := requireOID(content.Bytes, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
	if err != nil {
		return err
	}
	data, err := onlyDER(contentRest)
	if err != nil || !isDER(data, 2, 0, true) {
		return fmt.Errorf("detached CMS is not accepted")
	}
	octets, err := onlyDER(data.Bytes)
	if err != nil || !isDER(octets, 0, 4, false) || len(octets.Bytes) == 0 {
		return fmt.Errorf("empty CMS content")
	}
	seenCertificates, seenCRLs := false, false
	for len(rest) > 0 {
		var item asn1.RawValue
		item, rest, err = takeDER(rest)
		if err != nil {
			return err
		}
		if item.Class == 2 && item.IsCompound {
			if item.Tag == 0 && !seenCertificates && !seenCRLs {
				seenCertificates = true
				continue
			}
			if item.Tag == 1 && !seenCRLs {
				seenCRLs = true
				continue
			}
			return fmt.Errorf("ambiguous CMS certificates or revocation lists")
		}
		if !isDER(item, 0, 17, true) || len(rest) != 0 {
			return fmt.Errorf("invalid CMS signer set")
		}
		signer, err := onlyDER(item.Bytes)
		if err != nil || !isDER(signer, 0, 16, true) {
			return fmt.Errorf("exactly one CMS signer required")
		}
		v, r, err := takeDER(signer.Bytes)
		if err != nil || !isDER(v, 0, 2, false) {
			return fmt.Errorf("invalid signer version")
		}
		_, r, err = takeDER(r)
		if err != nil {
			return err
		} // SignerIdentifier
		digestAlg, _, err := takeDER(r)
		if err != nil || !isDER(digestAlg, 0, 16, true) {
			return fmt.Errorf("invalid signer digest")
		}
		if err := requireSHA256Algorithm(digestAlg); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("missing CMS signer")
}

func nativeCMSPrototype(cms []byte, pin string) ([]byte, error) {
	if !digest.MatchString(pin) {
		return nil, fmt.Errorf("invalid publisher pin")
	}
	if err := cmsShape(cms); err != nil {
		return nil, err
	}
	para := cryptVerifyMessagePara{Size: uint32(unsafe.Sizeof(cryptVerifyMessagePara{})), Encoding: 0x00010001}
	verify := windows.NewLazySystemDLL("crypt32.dll").NewProc("CryptVerifyMessageSignature")
	var size uint32
	ok, _, callErr := verify.Call(uintptr(unsafe.Pointer(&para)), 0, uintptr(unsafe.Pointer(&cms[0])), uintptr(len(cms)), 0, uintptr(unsafe.Pointer(&size)), 0)
	if ok == 0 || size == 0 || size > 8<<20 {
		return nil, fmt.Errorf("CMS verification failed: %v", callErr)
	}
	content := make([]byte, int(size))
	var signer *windows.CertContext
	ok, _, callErr = verify.Call(uintptr(unsafe.Pointer(&para)), 0, uintptr(unsafe.Pointer(&cms[0])), uintptr(len(cms)), uintptr(unsafe.Pointer(&content[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&signer)))
	if ok == 0 || signer == nil {
		return nil, fmt.Errorf("CMS signature invalid: %v", callErr)
	}
	defer windows.CertFreeCertificateContext(signer)
	if signer.EncodedCert == nil || signer.Length == 0 || signer.Length > 1<<20 {
		return nil, fmt.Errorf("invalid publisher certificate")
	}
	der := unsafe.Slice(signer.EncodedCert, int(signer.Length))
	if !nativeCertificateMatchesPin(der, pin) {
		return nil, fmt.Errorf("publisher mismatch")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("invalid publisher certificate")
	}
	allowed := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			allowed = true
		}
	}
	if !allowed {
		return nil, fmt.Errorf("code signing usage missing")
	}
	oid, err := windows.BytePtrFromString("1.3.6.1.5.5.7.3.3")
	if err != nil {
		return nil, err
	}
	chainParams := windows.CertChainPara{Size: uint32(unsafe.Sizeof(windows.CertChainPara{})), RequestedUsage: windows.CertUsageMatch{Usage: windows.CertEnhKeyUsage{Length: 1, UsageIdentifiers: &oid}}}
	var chain *windows.CertChainContext
	const cacheOnly uint32 = 0x00000004 | 0x80000000 | 0x40000000
	if err := windows.CertGetCertificateChain(0, signer, nil, signer.Store, &chainParams, cacheOnly, 0, &chain); err != nil || chain == nil {
		return nil, fmt.Errorf("publisher chain unavailable")
	}
	defer windows.CertFreeCertificateChain(chain)
	if chain.TrustStatus.ErrorStatus != 0 {
		return nil, fmt.Errorf("publisher chain trust status: 0x%08x", chain.TrustStatus.ErrorStatus)
	}
	policy := windows.CertChainPolicyPara{Size: uint32(unsafe.Sizeof(windows.CertChainPolicyPara{}))}
	status := windows.CertChainPolicyStatus{Size: uint32(unsafe.Sizeof(windows.CertChainPolicyStatus{}))}
	if err := windows.CertVerifyCertificateChainPolicy(windows.CERT_CHAIN_POLICY_BASE, chain, &policy, &status); err != nil || status.Error != 0 {
		return nil, fmt.Errorf("publisher chain policy rejected")
	}
	return content[:size], nil
}
