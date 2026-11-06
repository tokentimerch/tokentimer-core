package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestChainUsesOnlyExplicitLocalTrust(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Observed"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CRLDistributionPoints: []string{"http://crl.example.test/root.crl"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if !fullCRLDistributionPoints(leaf) {
		t.Fatal("simple full CRL distribution point not recognized")
	}
	if chains, err := VerifyChain(leaf, nil, []*x509.Certificate{root}, now); err != nil || len(chains) == 0 {
		t.Fatalf("valid client certificate: %v", err)
	}
	if _, err := VerifyChain(leaf, nil, nil, now); err == nil {
		t.Fatal("accepted without explicit trust anchor")
	}
	if _, err := VerifyChain(leaf, nil, []*x509.Certificate{root}, now.Add(2*time.Hour)); err == nil {
		t.Fatal("accepted expired chain")
	}
}
