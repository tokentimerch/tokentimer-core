//go:build windows

package chaincore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	usageMatchTypeAnd       = 0
	certChainPolicyBase     = 1
	x509AsnEncoding         = 0x00000001
	pkcs7AsnEncoding        = 0x00010000
	certStoreAddAlways      = 4
	certStoreProvMemory     = 2
	certCloseStoreForceFlag = 1
)

var (
	modcrypt32 = windows.NewLazySystemDLL("crypt32.dll")

	procCertCreateCertificateContext = modcrypt32.NewProc("CertCreateCertificateContext")
	procCertFreeCertificateContext   = modcrypt32.NewProc("CertFreeCertificateContext")
	procCertGetCertificateChain      = modcrypt32.NewProc("CertGetCertificateChain")
	procCertFreeCertificateChain     = modcrypt32.NewProc("CertFreeCertificateChain")
	procCertVerifyCertificateChainPolicy = modcrypt32.NewProc("CertVerifyCertificateChainPolicy")
	procCertOpenStore                = modcrypt32.NewProc("CertOpenStore")
	procCertAddEncodedCertificateToStore = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertCloseStore               = modcrypt32.NewProc("CertCloseStore")
)

type certUsageMatch struct {
	dwType  uint32
	usage   certEnhKeyUsage
}

type certEnhKeyUsage struct {
	cUsageIdentifier     uint32
	rgpszUsageIdentifier **byte
}

type certChainPara struct {
	cbSize                        uint32
	requestedUsage                certUsageMatch
	requestedIssuancePolicy       certUsageMatch
	dwUrlRetrievalTimeout         uint32
	fCheckRevocationFreshnessTime uint32
	dwRevocationFreshnessTime     uint32
	pftCacheResync                uintptr
	pStrongSignPara               uintptr
	dwStrongSignFlags             uint32
}

type certChainPolicyPara struct {
	cbSize           uint32
	dwFlags          uint32
	pvExtraPolicyPara uintptr
}

type certChainPolicyStatus struct {
	cbSize              uint32
	dwError             uint32
	lChainIndex         int32
	lElementIndex       int32
	pvExtraPolicyStatus uintptr
}

type certContext struct {
	dwCertEncodingType uint32
	pbCertEncoded      *byte
	cbCertEncoded      uint32
	pCertInfo          uintptr
	hCertStore         windows.Handle
}

type certSimpleChain struct {
	cbSize                      uint32
	trustStatus                 certTrustStatus
	cElement                    uint32
	rgpElement                  uintptr
	pTrustListInfo              uintptr
	fHasRevocationFreshnessTime uint32
	dwRevocationFreshnessTime   uint32
}

type certTrustStatus struct {
	dwErrorStatus uint32
	dwInfoStatus  uint32
}

type certChainContext struct {
	cbSize                      uint32
	trustStatus                 certTrustStatus
	cChain                      uint32
	rgpChain                    uintptr
	cLowerQualityChainContext   uint32
	rgpLowerQualityChainContext uintptr
	fHasRevocationFreshnessTime uint32
	dwRevocationFreshnessTime   uint32
	dwCreateFlags               uint32
	ChainId                     windows.GUID
}

type certChainElement struct {
	cbSize                      uint32
	pCertContext                *certContext
	trustStatus                 certTrustStatus
	pRevocationInfo             uintptr
	pIssuanceUsage              uintptr
	pApplicationUsage           uintptr
	pwszExtendedErrorInfo       *uint16
}

// Verify builds a chain with end-entity + intermediate revocation checking
// and Server Authentication application policy, then maps CryptoAPI trust
// flags to a stable verdict (ADR-0014 decision 6).
func Verify(leafDER []byte, caKeySha256 string, extraCerts [][]byte, revocationMode string) (Result, error) {
	if len(leafDER) == 0 {
		return Result{Verdict: VerdictInvalid, Error: "leaf certificate is empty"}, nil
	}
	if _, err := hex.DecodeString(caKeySha256); err != nil || len(caKeySha256) != 64 {
		return Result{Verdict: VerdictInvalid, Error: "caKeySha256 must be 64 hex characters"}, nil
	}

	leafCtx, _, callErr := procCertCreateCertificateContext.Call(
		uintptr(x509AsnEncoding|pkcs7AsnEncoding),
		uintptr(unsafe.Pointer(&leafDER[0])),
		uintptr(len(leafDER)),
	)
	if leafCtx == 0 {
		return Result{Verdict: VerdictInvalid, Error: fmt.Sprintf("CertCreateCertificateContext failed: %v", callErr)}, nil
	}
	defer procCertFreeCertificateContext.Call(leafCtx)

	var extraStore windows.Handle
	if len(extraCerts) > 0 {
		h, _, err := procCertOpenStore.Call(
			uintptr(certStoreProvMemory),
			0,
			0,
			0,
			0,
		)
		if h == 0 {
			return Result{Verdict: VerdictInvalid, Error: fmt.Sprintf("CertOpenStore failed: %v", err)}, nil
		}
		extraStore = windows.Handle(h)
		defer procCertCloseStore.Call(h, uintptr(certCloseStoreForceFlag))
		for _, cert := range extraCerts {
			if len(cert) == 0 {
				continue
			}
			r, _, err := procCertAddEncodedCertificateToStore.Call(
				h,
				uintptr(x509AsnEncoding|pkcs7AsnEncoding),
				uintptr(unsafe.Pointer(&cert[0])),
				uintptr(len(cert)),
				uintptr(certStoreAddAlways),
				0,
			)
			if r == 0 {
				return Result{Verdict: VerdictInvalid, Error: fmt.Sprintf("CertAddEncodedCertificateToStore failed: %v", err)}, nil
			}
		}
	}

	oid, err := windows.BytePtrFromString("1.3.6.1.5.5.7.3.1")
	if err != nil {
		return Result{Verdict: VerdictInvalid, Error: err.Error()}, nil
	}
	oids := []*byte{oid}

	para := certChainPara{
		cbSize: uint32(unsafe.Sizeof(certChainPara{})),
		requestedUsage: certUsageMatch{
			dwType: usageMatchTypeAnd,
			usage: certEnhKeyUsage{
				cUsageIdentifier:     1,
				rgpszUsageIdentifier: &oids[0],
			},
		},
	}

	// Mutually exclusive CERT_CHAIN_REVOCATION_CHECK_* group: use only
	// CHAIN_EXCLUDE_ROOT (leaf + intermediates, root excluded).
	flags := uint32(CertChainRevocationCheckChainExcludeRoot)
	var chainCtx uintptr
	r, _, callErr := procCertGetCertificateChain.Call(
		0, // HCCE_CURRENT_USER default engine; machine context still uses local machine roots
		leafCtx,
		0,
		uintptr(extraStore),
		uintptr(unsafe.Pointer(&para)),
		uintptr(flags),
		0,
		uintptr(unsafe.Pointer(&chainCtx)),
	)
	if r == 0 || chainCtx == 0 {
		return Result{Verdict: VerdictInvalid, Error: fmt.Sprintf("CertGetCertificateChain failed: %v", callErr)}, nil
	}
	defer procCertFreeCertificateChain.Call(chainCtx)

	chain := (*certChainContext)(unsafe.Pointer(chainCtx))
	trust := chain.trustStatus.dwErrorStatus

	// Pin check against the immediate issuer before mapping other failures.
	if pinVerdict := checkIssuerPin(chain, caKeySha256); pinVerdict != nil {
		return *pinVerdict, nil
	}

	policyPara := certChainPolicyPara{cbSize: uint32(unsafe.Sizeof(certChainPolicyPara{}))}
	policyStatus := certChainPolicyStatus{cbSize: uint32(unsafe.Sizeof(certChainPolicyStatus{}))}
	policyOK, _, policyCallErr := procCertVerifyCertificateChainPolicy.Call(
		uintptr(certChainPolicyBase),
		chainCtx,
		uintptr(unsafe.Pointer(&policyPara)),
		uintptr(unsafe.Pointer(&policyStatus)),
	)
	// A failed API invocation must not be treated as policyError=0 / valid.
	if policyOK == 0 {
		return Result{
			Verdict: VerdictInvalid,
			Error:   fmt.Sprintf("CertVerifyCertificateChainPolicy failed: %v", policyCallErr),
		}, nil
	}

	_ = revocationMode // require vs best-effort is applied by the JS caller
	return MapChainTrust(trust, policyStatus.dwError), nil
}

func checkIssuerPin(chain *certChainContext, caKeySha256 string) *Result {
	if chain.cChain == 0 || chain.rgpChain == 0 {
		return &Result{Verdict: VerdictInvalid, Error: "certificate chain is empty"}
	}
	simpleChains := unsafe.Slice((**certSimpleChain)(unsafe.Pointer(chain.rgpChain)), chain.cChain)
	simple := simpleChains[0]
	if simple == nil || simple.cElement < 2 || simple.rgpElement == 0 {
		return &Result{Verdict: VerdictInvalid, Error: "certificate chain has no issuer element"}
	}
	// Element 0 is the leaf; element 1 is the issuing CA.
	elements := unsafe.Slice((**certChainElement)(unsafe.Pointer(simple.rgpElement)), simple.cElement)
	issuerElem := elements[1]
	if issuerElem == nil || issuerElem.pCertContext == nil {
		return &Result{Verdict: VerdictInvalid, Error: "issuer certificate context missing"}
	}
	ctx := issuerElem.pCertContext
	if ctx.pbCertEncoded == nil || ctx.cbCertEncoded == 0 {
		return &Result{Verdict: VerdictInvalid, Error: "issuer certificate encoding missing"}
	}
	der := unsafe.Slice(ctx.pbCertEncoded, ctx.cbCertEncoded)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return &Result{Verdict: VerdictInvalid, Error: fmt.Sprintf("issuer certificate parse failed: %v", err)}
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	got := hex.EncodeToString(sum[:])
	if got != caKeySha256 {
		return &Result{
			Verdict: VerdictCAKeyChanged,
			Error:   fmt.Sprintf("issuing CA key sha256 %s does not match pin", got),
		}
	}
	return nil
}
