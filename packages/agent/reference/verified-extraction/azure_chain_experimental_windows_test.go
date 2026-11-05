//go:build windows

package verifiedextraction

// Native chain experiment only. It uses private in-memory certificate stores,
// not the machine/user trust store and not the experimental launcher verifier.
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type isolatedChainEngineConfig struct {
	size                                             uint32
	restrictedRoot, restrictedTrust, restrictedOther windows.Handle
	additionalCount                                  uint32
	additionalStores                                 *windows.Handle
	flags, urlTimeout, maxCache, cycleModulus        uint32
	exclusiveRoot, exclusivePeople                   windows.Handle
	exclusiveFlags                                   uint32
}

var certCreateEngine = experimentalCrypt32.NewProc("CertCreateCertificateChainEngine")
var certFreeEngine = experimentalCrypt32.NewProc("CertFreeCertificateChainEngine")
var certAddEncoded = experimentalCrypt32.NewProc("CertAddEncodedCertificateToStore")
var certAddCRL = experimentalCrypt32.NewProc("CertAddEncodedCRLToStore")

func makeChainFixture(t *testing.T, usage x509.ExtKeyUsage, revoked bool) ([]byte, []byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Private Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Private Test Leaf"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, CRLDistributionPoints: []string{"http://example.invalid/fixture.crl"}}
	if usage == x509.ExtKeyUsageCodeSigning {
		leafTemplate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 97, 123, 456, 789}}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	if revoked {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: now.Add(-time.Second)}}
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, list, root, key)
	if err != nil {
		t.Fatal(err)
	}
	return rootDER, leafDER, crlDER
}

func isolatedChain(rootDER, leafDER, crlDER []byte, usage string, when ...time.Time) (uint32, error) {
	rootStore, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CertCloseStore(rootStore, 0)
	additional, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CertCloseStore(additional, 0)
	r, _, e := certAddEncoded.Call(uintptr(rootStore), windows.X509_ASN_ENCODING, uintptr(unsafe.Pointer(&rootDER[0])), uintptr(len(rootDER)), windows.CERT_STORE_ADD_ALWAYS, 0)
	if r == 0 {
		return 0, fmt.Errorf("add root: %w", e)
	}
	if len(crlDER) > 0 {
		r, _, e = certAddCRL.Call(uintptr(additional), windows.X509_ASN_ENCODING, uintptr(unsafe.Pointer(&crlDER[0])), uintptr(len(crlDER)), windows.CERT_STORE_ADD_ALWAYS, 0)
		if r == 0 {
			return 0, fmt.Errorf("add CRL: %w", e)
		}
	}
	config := isolatedChainEngineConfig{exclusiveRoot: rootStore}
	config.size = uint32(unsafe.Sizeof(config))
	var engine windows.Handle
	r, _, e = certCreateEngine.Call(uintptr(unsafe.Pointer(&config)), uintptr(unsafe.Pointer(&engine)))
	if r == 0 {
		return 0, fmt.Errorf("create chain engine: %w", e)
	}
	defer certFreeEngine.Call(uintptr(engine))
	leaf, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &leafDER[0], uint32(len(leafDER)))
	if err != nil {
		return 0, err
	}
	defer windows.CertFreeCertificateContext(leaf)
	oid, err := windows.BytePtrFromString(usage)
	if err != nil {
		return 0, err
	}
	para := windows.CertChainPara{Size: uint32(unsafe.Sizeof(windows.CertChainPara{}))}
	para.RequestedUsage.Usage.Length = 1
	para.RequestedUsage.Usage.UsageIdentifiers = &oid
	var chain *windows.CertChainContext
	var verifyTime *windows.Filetime
	if len(when) == 1 {
		value := windows.NsecToFiletime(when[0].UnixNano())
		verifyTime = &value
	} else if len(when) > 1 {
		return 0, fmt.Errorf("ambiguous verification time")
	}
	const chainCacheOnly = 0x00000004
	const chainRevocationExcludeRoot = 0x40000000
	const revocationCacheOnly = 0x80000000
	if err = windows.CertGetCertificateChain(engine, leaf, verifyTime, additional, &para, chainCacheOnly|chainRevocationExcludeRoot|revocationCacheOnly, 0, &chain); err != nil {
		return 0, err
	}
	defer windows.CertFreeCertificateChain(chain)
	return chain.TrustStatus.ErrorStatus, nil
}

func TestAzureIsolatedChainRevocation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		usage x509.ExtKeyUsage
		oid   string
	}{
		{"publisher", x509.ExtKeyUsageCodeSigning, "1.3.6.1.5.5.7.3.3"},
		{"timestamp", x509.ExtKeyUsageTimeStamping, "1.3.6.1.5.5.7.3.8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, leaf, crl := makeChainFixture(t, tc.usage, false)
			status, err := isolatedChain(root, leaf, crl, tc.oid)
			if err != nil {
				t.Fatal(err)
			}
			if status != 0 {
				t.Fatalf("valid chain error: %#x", status)
			}
			status, err = isolatedChain(root, leaf, crl, tc.oid, time.Now().Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if status&windows.CERT_TRUST_IS_NOT_TIME_VALID == 0 {
				t.Fatalf("expired chain not rejected: %#x", status)
			}
			status, err = isolatedChain(root, leaf, nil, tc.oid)
			if err != nil {
				t.Fatal(err)
			}
			if status == 0 {
				t.Fatal("missing CRL accepted")
			}
			status, err = isolatedChain(root, leaf, crl, "1.3.6.1.5.5.7.3.1")
			if err != nil {
				t.Fatal(err)
			}
			if status == 0 {
				t.Fatal("wrong EKU accepted")
			}
			otherRoot, _, _ := makeChainFixture(t, tc.usage, false)
			status, err = isolatedChain(otherRoot, leaf, crl, tc.oid)
			if err != nil {
				t.Fatal(err)
			}
			if status == 0 {
				t.Fatal("untrusted issuer accepted")
			}
			if tc.usage == x509.ExtKeyUsageCodeSigning {
				status, err = isolatedChain(root, leaf, crl, "1.3.6.1.4.1.311.97.123.456.789")
				if err != nil {
					t.Fatal(err)
				}
				if status != 0 {
					t.Fatalf("expected publisher profile rejected: %#x", status)
				}
				status, err = isolatedChain(root, leaf, crl, "1.3.6.1.4.1.311.97.123.456.788")
				if err != nil {
					t.Fatal(err)
				}
				if status == 0 {
					t.Fatal("wrong publisher profile accepted")
				}
			}
			root, leaf, crl = makeChainFixture(t, tc.usage, true)
			status, err = isolatedChain(root, leaf, crl, tc.oid)
			if err != nil {
				t.Fatal(err)
			}
			if status&windows.CERT_TRUST_IS_REVOKED == 0 {
				t.Fatalf("revoked certificate not detected: %#x", status)
			}
		})
	}
}
