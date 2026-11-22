//go:build windows

package verifiedextraction

// All test identities, signatures and CRLs are generated in memory. The CMS
// encoder here is test-only; it is not a release signing implementation.
import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"sort"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type testIdentity struct {
	root, cert []byte
	key        *rsa.PrivateKey
	ca         *x509.Certificate
	caKey      *rsa.PrivateKey
}

func testIdentityCreate(t *testing.T, timestamp bool) testIdentity {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fixture Signer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, CRLDistributionPoints: []string{"http://example.invalid/test.crl"}}
	if timestamp {
		eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}
	} else {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		leaf.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 97, 123, 456, 789}}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return testIdentity{rootDER, der, key, root, caKey}
}

func testCRL(t *testing.T, identity testIdentity, revoked bool) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	if revoked {
		list.Number = big.NewInt(2)
		list.ThisUpdate = now
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: now.Add(-30 * time.Second)}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, identity.ca, identity.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testPrivateEngine(t *testing.T, root, crl []byte) experimentalChainContext {
	t.Helper()
	roots, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CertCloseStore(roots, 0) })
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CertCloseStore(store, 0) })
	r, _, e := certAddEncoded.Call(uintptr(roots), windows.X509_ASN_ENCODING, uintptr(unsafe.Pointer(&root[0])), uintptr(len(root)), windows.CERT_STORE_ADD_ALWAYS, 0)
	if r == 0 {
		t.Fatal(e)
	}
	if len(crl) > 0 {
		r, _, e = certAddCRL.Call(uintptr(store), windows.X509_ASN_ENCODING, uintptr(unsafe.Pointer(&crl[0])), uintptr(len(crl)), windows.CERT_STORE_ADD_ALWAYS, 0)
		if r == 0 {
			t.Fatal(e)
		}
	}
	config := isolatedChainEngineConfig{exclusiveRoot: roots}
	config.size = uint32(unsafe.Sizeof(config))
	var engine windows.Handle
	r, _, e = certCreateEngine.Call(uintptr(unsafe.Pointer(&config)), uintptr(unsafe.Pointer(&engine)))
	if r == 0 {
		t.Fatal(e)
	}
	t.Cleanup(func() { certFreeEngine.Call(uintptr(engine)) })
	return experimentalChainContext{engine: engine, store: store}
}

func testDER(t *testing.T, v any) []byte {
	t.Helper()
	b, e := asn1.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func testWrap(t *testing.T, class, tag int, body []byte) []byte {
	t.Helper()
	return testDER(t, asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: body})
}
func testJoin(parts ...[]byte) []byte              { return bytes.Join(parts, nil) }
func testSeq(t *testing.T, parts ...[]byte) []byte { return testWrap(t, 0, 16, testJoin(parts...)) }
func testSet(t *testing.T, parts ...[]byte) []byte {
	sort.Slice(parts, func(i, j int) bool { return bytes.Compare(parts[i], parts[j]) < 0 })
	return testWrap(t, 0, 17, testJoin(parts...))
}
func testOID(t *testing.T, v ...int) []byte { return testDER(t, asn1.ObjectIdentifier(v)) }

var testDataOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
var testTSTOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

func testCMS(t *testing.T, content []byte, contentType asn1.ObjectIdentifier, id testIdentity, timestampToken []byte, signingCertAttr bool) ([]byte, []byte) {
	t.Helper()
	cert, err := x509.ParseCertificate(id.cert)
	if err != nil {
		t.Fatal(err)
	}
	shaAlg := testSeq(t, testOID(t, 2, 16, 840, 1, 101, 3, 4, 2, 1), []byte{5, 0})
	rsaAlg := testSeq(t, testOID(t, 1, 2, 840, 113549, 1, 1, 1), []byte{5, 0})
	digest := sha256.Sum256(content)
	attrType := testSeq(t, testOID(t, 1, 2, 840, 113549, 1, 9, 3), testSet(t, testDER(t, contentType)))
	attrDigest := testSeq(t, testOID(t, 1, 2, 840, 113549, 1, 9, 4), testSet(t, testDER(t, digest[:])))
	attrs := [][]byte{attrType, attrDigest}
	if signingCertAttr {
		h := sha256.Sum256(id.cert)
		ess := testSeq(t, testSeq(t, testSeq(t, testDER(t, h[:]))))
		attrs = append(attrs, testSeq(t, testOID(t, 1, 2, 840, 113549, 1, 9, 16, 2, 47), testSet(t, ess)))
	}
	signedSet := testSet(t, attrs...)
	signedHash := sha256.Sum256(signedSet)
	sig, err := rsa.SignPKCS1v15(rand.Reader, id.key, crypto.SHA256, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}
	signedCtx := append([]byte(nil), signedSet...)
	signedCtx[0] = 0xa0
	parts := [][]byte{testDER(t, 1), testSeq(t, cert.RawIssuer, testDER(t, cert.SerialNumber)), shaAlg, signedCtx, rsaAlg, testDER(t, sig)}
	if timestampToken != nil {
		attr := testSeq(t, testOID(t, 1, 3, 6, 1, 4, 1, 311, 3, 3, 1), testSet(t, timestampToken))
		parts = append(parts, testWrap(t, 2, 1, attr))
	}
	signer := testSeq(t, parts...)
	encap := testSeq(t, testDER(t, contentType), testWrap(t, 2, 0, testDER(t, content)))
	certificates := testWrap(t, 2, 0, testJoin(id.cert, id.root))
	version := 1
	if !contentType.Equal(testDataOID) {
		version = 3
	}
	data := testSeq(t, testDER(t, version), testSet(t, shaAlg), encap, certificates, testSet(t, signer))
	return testSeq(t, testOID(t, 1, 2, 840, 113549, 1, 7, 2), testWrap(t, 2, 0, data)), sig
}

func TestAzureExperimentalFullPrivatePKI(t *testing.T) {
	publisher := testIdentityCreate(t, false)
	tsa := testIdentityCreate(t, true)
	payload := []byte(`{"fixture":true}`)
	_, publisherSig := testCMS(t, payload, testDataOID, publisher, nil, false)
	imprint := sha256.Sum256(publisherSig)
	alg := testSeq(t, testOID(t, 2, 16, 840, 1, 101, 3, 4, 2, 1), []byte{5, 0})
	clock, err := asn1.MarshalWithParams(time.Now().UTC().Truncate(time.Second), "generalized")
	if err != nil {
		t.Fatal(err)
	}
	info := testSeq(t, testDER(t, 1), testOID(t, 1, 2, 3, 4), testSeq(t, alg, testDER(t, imprint[:])), testDER(t, 99), clock)
	token, _ := testCMS(t, info, testTSTOID, tsa, nil, true)
	cms, _ := testCMS(t, payload, testDataOID, publisher, token, false)
	pubHash := sha256.Sum256(publisher.root)
	tsaHash := sha256.Sum256(tsa.root)
	policy := azureCMSExperimentalPolicy{hex.EncodeToString(pubHash[:]), hex.EncodeToString(tsaHash[:]), "1.3.6.1.4.1.311.97.123.456.789"}
	pubContext := testPrivateEngine(t, publisher.root, testCRL(t, publisher, false))
	tsaContext := testPrivateEngine(t, tsa.root, testCRL(t, tsa, false))
	content, err := verifyAzureCMSExperimentalWithContexts(cms, policy, pubContext, tsaContext)
	if err != nil {
		t.Fatalf("valid private CMS: %v", err)
	}
	if !bytes.Equal(content, payload) {
		t.Fatal("incorrect verified content")
	}
	bad := policy
	bad.ProfileEKU = "1.3.6.1.4.1.311.97.123.456.788"
	if _, err = verifyAzureCMSExperimentalWithContexts(cms, bad, pubContext, tsaContext); err == nil {
		t.Fatal("wrong profile accepted")
	}
	bad = policy
	bad.PublisherIssuerSHA256 = hex.EncodeToString(tsaHash[:])
	if _, err = verifyAzureCMSExperimentalWithContexts(cms, bad, pubContext, tsaContext); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	revoked := testPrivateEngine(t, publisher.root, testCRL(t, publisher, true))
	if _, err = verifyAzureCMSExperimentalWithContexts(cms, policy, revoked, tsaContext); err == nil {
		t.Fatal("revoked publisher accepted")
	}
	bad = policy
	bad.TimestampIssuerSHA256 = hex.EncodeToString(pubHash[:])
	if _, err = verifyAzureCMSExperimentalWithContexts(cms, bad, pubContext, tsaContext); err == nil {
		t.Fatal("wrong timestamp issuer accepted")
	}
	revokedTSA := testPrivateEngine(t, tsa.root, testCRL(t, tsa, true))
	if _, err = verifyAzureCMSExperimentalWithContexts(cms, policy, pubContext, revokedTSA); err == nil {
		t.Fatal("revoked timestamp signer accepted")
	}
	missingCRL := testPrivateEngine(t, tsa.root, nil)
	if _, err = verifyAzureCMSExperimentalWithContexts(cms, policy, pubContext, missingCRL); err == nil {
		t.Fatal("missing timestamp CRL accepted")
	}
	modified := bytes.Clone(cms)
	pos := bytes.Index(modified, payload)
	if pos < 0 {
		t.Fatal("CMS payload not found")
	}
	modified[pos] ^= 1
	if _, err = verifyAzureCMSExperimentalWithContexts(modified, policy, pubContext, tsaContext); err == nil {
		t.Fatal("tampered CMS accepted")
	}
}
