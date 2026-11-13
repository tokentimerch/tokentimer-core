package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestObservedLeafCRLReconciliation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Observed"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), CRLDistributionPoints: []string{"http://pki.example.test/root.crl"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chains, err := VerifyChain(leaf, nil, []*x509.Certificate{root}, now)
	if err != nil {
		t.Fatal(err)
	}
	makeCRL := func(revoked bool, until time.Time) []byte {
		list := &x509.RevocationList{Number: big.NewInt(5), ThisUpdate: now.Add(-time.Minute), NextUpdate: until}
		if revoked {
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: now.Add(-time.Minute)}}
		}
		der, err := x509.CreateRevocationList(rand.Reader, list, root, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for _, tc := range []struct {
		name        string
		der         []byte
		unavailable bool
		want        string
	}{
		{"valid", makeCRL(false, now.Add(time.Hour)), false, "good"},
		{"revoked externally", makeCRL(true, now.Add(time.Hour)), false, "revoked"},
		{"stale", makeCRL(false, now.Add(-time.Second)), false, "unknown"},
		{"responder offline", nil, true, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetch := func(_ context.Context, url string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
				if url != "http://pki.example.test/root.crl" || tc.unavailable {
					return nil, fmt.Errorf("unavailable")
				}
				return tc.der, nil
			}
			got := checkChain(context.Background(), chains[0], []string{"http://pki.example.test"}, []*x509.Certificate{root}, now, fetch)
			if got.Verdict != tc.want {
				t.Fatalf("got %+v, want %s", got, tc.want)
			}
		})
	}
}
