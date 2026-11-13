//go:build windows

package verifiedextraction

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var experimentalCertAddEncoded = experimentalCrypt32.NewProc("CertAddEncodedCertificateToStore")

// Default zero values use the system chain engine and a private memory store.
// A nonzero engine and store are supplied only by the isolated PKI tests.
type experimentalChainContext struct{ engine, store windows.Handle }

func experimentalVerifyChain(leafDER []byte, extra [][]byte, usage, pin string, at time.Time, test experimentalChainContext) error {
	if len(leafDER) == 0 || len(leafDER) > 1<<20 || len(extra) > 100 || !digest.MatchString(pin) {
		return fmt.Errorf("invalid chain input")
	}
	store := test.store
	if store == 0 {
		var err error
		store, err = windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
		if err != nil {
			return err
		}
		defer windows.CertCloseStore(store, 0)
	}
	for _, der := range extra {
		if len(der) == 0 || len(der) > 1<<20 {
			return fmt.Errorf("invalid additional certificate")
		}
		r, _, e := experimentalCertAddEncoded.Call(uintptr(store), windows.X509_ASN_ENCODING, uintptr(unsafe.Pointer(&der[0])), uintptr(len(der)), windows.CERT_STORE_ADD_ALWAYS, 0)
		runtime.KeepAlive(der)
		if r == 0 {
			return fmt.Errorf("add chain certificate: %w", e)
		}
	}
	leaf, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &leafDER[0], uint32(len(leafDER)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(leaf)
	oid, err := windows.BytePtrFromString(usage)
	if err != nil {
		return err
	}
	para := windows.CertChainPara{Size: uint32(unsafe.Sizeof(windows.CertChainPara{}))}
	para.RequestedUsage.Usage.Length = 1
	para.RequestedUsage.Usage.UsageIdentifiers = &oid
	ft := windows.NsecToFiletime(at.UnixNano())
	var chain *windows.CertChainContext
	const cacheOnly = 0x00000004
	const revocationExcludeRoot = 0x40000000
	const revocationCacheOnly = 0x80000000
	if err = windows.CertGetCertificateChain(test.engine, leaf, &ft, store, &para, cacheOnly|revocationExcludeRoot|revocationCacheOnly, 0, &chain); err != nil {
		return err
	}
	defer windows.CertFreeCertificateChain(chain)
	if chain == nil || chain.TrustStatus.ErrorStatus != 0 || chain.ChainCount != 1 || chain.Chains == nil {
		return fmt.Errorf("untrusted or ambiguous chain")
	}
	policy := windows.CertChainPolicyPara{Size: uint32(unsafe.Sizeof(windows.CertChainPolicyPara{}))}
	status := windows.CertChainPolicyStatus{Size: uint32(unsafe.Sizeof(windows.CertChainPolicyStatus{}))}
	if err = windows.CertVerifyCertificateChainPolicy(1, chain, &policy, &status); err != nil {
		return err
	}
	if status.Error != 0 {
		return fmt.Errorf("chain policy rejected")
	}
	simple := *chain.Chains
	if simple == nil || simple.NumElements < 2 || simple.NumElements > 100 || simple.Elements == nil {
		return fmt.Errorf("invalid issuer chain")
	}
	found := false
	for _, element := range unsafe.Slice(simple.Elements, int(simple.NumElements))[1:] {
		if element == nil || element.CertContext == nil || element.CertContext.EncodedCert == nil || element.CertContext.Length == 0 || element.CertContext.Length > 1<<20 {
			return fmt.Errorf("invalid issuer certificate")
		}
		raw := unsafe.Slice(element.CertContext.EncodedCert, int(element.CertContext.Length))
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) == pin {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("issuer pin mismatch")
	}
	return nil
}
