package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestCRLVerification(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	crl := &x509.RevocationList{Number: big.NewInt(3), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(42), RevocationTime: now.Add(-time.Minute)}}}
	der, err := x509.CreateRevocationList(rand.Reader, crl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		serial int64
		at     time.Time
		want   string
	}{
		{"revoked", 42, now, "revoked"}, {"not listed", 43, now, "good"}, {"expired list", 43, now.Add(2 * time.Hour), "unknown"}, {"not yet valid list", 43, now.Add(-time.Hour), "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, checkErr := CheckCRL(der, issuer, big.NewInt(tc.serial), tc.at, true)
			if got != tc.want {
				t.Fatalf("got %s want %s: %v", got, tc.want, checkErr)
			}
		})
	}
	bad := append([]byte(nil), der...)
	bad[len(bad)-1] ^= 1
	if got, _, err := CheckCRL(bad, issuer, big.NewInt(43), now, true); got != "unknown" || err == nil {
		t.Fatalf("tampered CRL accepted: %s %v", got, err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	other, err := x509.ParseCertificate(otherDER)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := CheckCRL(der, other, big.NewInt(43), now, true); got != "unknown" || err == nil {
		t.Fatalf("same-name wrong issuer accepted: %s %v", got, err)
	}
	if got, _, err := CheckCRL(der, nil, big.NewInt(43), now, true); got != "unknown" || err == nil {
		t.Fatalf("missing issuer accepted: %s %v", got, err)
	}
	crl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{0x02, 0x01, 0x01}}}
	deltaDER, err := x509.CreateRevocationList(rand.Reader, crl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := CheckCRL(deltaDER, issuer, big.NewInt(43), now, true); got != "unknown" || err == nil {
		t.Fatalf("delta CRL incorrectly treated as complete: %s %v", got, err)
	}
	crl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: []byte{0x30, 0x00}}}
	baseWithDelta, err := x509.CreateRevocationList(rand.Reader, crl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := CheckCRL(baseWithDelta, issuer, big.NewInt(43), now, true); got != "unknown" || err == nil {
		t.Fatalf("base CRL with an unprocessed delta accepted: %s %v", got, err)
	}
	if got, _, err := CheckCRL(der, issuer, big.NewInt(43), now, false); got != "unknown" || err == nil {
		t.Fatalf("unverified coverage incorrectly accepted: %s %v", got, err)
	}
}
