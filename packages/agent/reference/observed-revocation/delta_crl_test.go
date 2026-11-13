package revocation

import (
	"context"
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

func TestBaseAndDeltaCRL(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(v any) []byte {
		b, e := asn1.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	uri := encode(asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte("http://ca.test/delta.crl")})
	fullName := encode(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: uri})
	pointName := encode(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: fullName})
	point := encode(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: pointName})
	freshest := pkix.Extension{Id: freshestCRLOID, Value: encode(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: point})}
	indicator := pkix.Extension{Id: deltaIndicatorOID, Critical: true, Value: encode(big.NewInt(10))}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}
	makeList := func(number int64, extensions []pkix.Extension, entries []x509.RevocationListEntry, expiration time.Time) []byte {
		b, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now.Add(-time.Minute), NextUpdate: expiration, ExtraExtensions: extensions, RevokedCertificateEntries: entries}, issuer, key)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	entry := func(serial int64, reason int) x509.RevocationListEntry {
		return x509.RevocationListEntry{SerialNumber: big.NewInt(serial), RevocationTime: now.Add(-time.Minute), ReasonCode: reason}
	}
	base := makeList(10, []pkix.Extension{freshest}, []x509.RevocationListEntry{entry(42, 6)}, now.Add(time.Hour))
	for _, tc := range []struct {
		name  string
		delta []byte
		want  string
	}{
		{"held remains revoked", makeList(11, []pkix.Extension{indicator}, nil, now.Add(time.Hour)), "revoked"},
		{"release from hold", makeList(11, []pkix.Extension{indicator}, []x509.RevocationListEntry{entry(42, 8)}, now.Add(time.Hour)), "good"},
		{"newly revoked", makeList(11, []pkix.Extension{indicator}, []x509.RevocationListEntry{entry(42, 5)}, now.Add(time.Hour)), "revoked"},
		{"wrong number", makeList(9, []pkix.Extension{indicator}, nil, now.Add(time.Hour)), "unknown"},
		{"simultaneous complete CRL", makeList(10, []pkix.Extension{indicator}, nil, now.Add(time.Hour)), "revoked"},
		{"simultaneous consistent entry", makeList(10, []pkix.Extension{indicator}, []x509.RevocationListEntry{entry(42, 6)}, now.Add(time.Hour)), "revoked"},
		{"simultaneous contradictory removal", makeList(10, []pkix.Extension{indicator}, []x509.RevocationListEntry{entry(42, 8)}, now.Add(time.Hour)), "unknown"},
		{"expired", makeList(11, []pkix.Extension{indicator}, nil, now.Add(-time.Second)), "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetch := func(_ context.Context, _ string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
				return tc.delta, nil
			}
			got, _, err := checkBaseAndDelta(context.Background(), base, leaf, issuer, nil, nil, now, true, fetch)
			if got != tc.want {
				t.Fatalf("got %q want %q: %v", got, tc.want, err)
			}
		})
	}
	t.Run("missing and forged deltas fail closed", func(t *testing.T) {
		for _, data := range [][]byte{nil, []byte("not a CRL")} {
			fetch := func(_ context.Context, _ string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
				return data, nil
			}
			got, _, _ := checkBaseAndDelta(context.Background(), base, leaf, issuer, nil, nil, now, true, fetch)
			if got != "unknown" {
				t.Fatalf("unavailable delta returned %q", got)
			}
		}
	})
	t.Run("permanent revocation cannot be removed", func(t *testing.T) {
		permanent := makeList(10, []pkix.Extension{freshest}, []x509.RevocationListEntry{entry(42, 5)}, now.Add(time.Hour))
		delta := makeList(11, []pkix.Extension{indicator}, []x509.RevocationListEntry{entry(42, 8)}, now.Add(time.Hour))
		fetch := func(_ context.Context, _ string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
			return delta, nil
		}
		got, _, _ := checkBaseAndDelta(context.Background(), permanent, leaf, issuer, nil, nil, now, true, fetch)
		if got != "unknown" {
			t.Fatalf("invalid removal returned %q", got)
		}
	})
	t.Run("delta can introduce revocation", func(t *testing.T) {
		clearBase := makeList(10, []pkix.Extension{freshest}, nil, now.Add(time.Hour))
		delta := makeList(11, []pkix.Extension{indicator}, []x509.RevocationListEntry{entry(42, 5)}, now.Add(time.Hour))
		fetch := func(_ context.Context, _ string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
			return delta, nil
		}
		got, _, err := checkBaseAndDelta(context.Background(), clearBase, leaf, issuer, nil, nil, now, true, fetch)
		if got != "revoked" {
			t.Fatalf("delta entry returned %q: %v", got, err)
		}
	})
	t.Run("future entry cannot assert good", func(t *testing.T) {
		clearBase := makeList(10, []pkix.Extension{freshest}, nil, now.Add(time.Hour))
		future := x509.RevocationListEntry{SerialNumber: big.NewInt(42), RevocationTime: now.Add(time.Minute), ReasonCode: 5}
		delta := makeList(11, []pkix.Extension{indicator}, []x509.RevocationListEntry{future}, now.Add(time.Hour))
		fetch := func(_ context.Context, _ string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
			return delta, nil
		}
		got, _, _ := checkBaseAndDelta(context.Background(), clearBase, leaf, issuer, nil, nil, now, true, fetch)
		if got != "unknown" {
			t.Fatalf("future entry returned %q", got)
		}
	})
	t.Run("untrusted delta cannot assert good", func(t *testing.T) {
		delta := makeList(11, []pkix.Extension{indicator}, nil, now.Add(time.Hour))
		delta[len(delta)-1] ^= 1
		fetch := func(_ context.Context, _ string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
			return delta, nil
		}
		got, _, _ := checkBaseAndDelta(context.Background(), base, leaf, issuer, nil, nil, now, true, fetch)
		if got != "unknown" {
			t.Fatalf("forged delta returned %q", got)
		}
	})
	t.Run("delta applies only to compatible base", func(t *testing.T) {
		badIndicator := pkix.Extension{Id: deltaIndicatorOID, Critical: true, Value: encode(big.NewInt(11))}
		delta := makeList(12, []pkix.Extension{badIndicator}, nil, now.Add(time.Hour))
		fetch := func(_ context.Context, _ string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
			return delta, nil
		}
		got, _, _ := checkBaseAndDelta(context.Background(), base, leaf, issuer, nil, nil, now, true, fetch)
		if got != "unknown" {
			t.Fatalf("incompatible base returned %q", got)
		}
	})
	t.Run("certificate discovery fetches base and delta", func(t *testing.T) {
		leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "observed"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), CRLDistributionPoints: []string{"http://ca.test/base.crl"}}
		encoded, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		observed, err := x509.ParseCertificate(encoded)
		if err != nil {
			t.Fatal(err)
		}
		clearBase := makeList(10, []pkix.Extension{freshest}, nil, now.Add(time.Hour))
		delta := makeList(11, []pkix.Extension{indicator}, []x509.RevocationListEntry{entry(42, 5)}, now.Add(time.Hour))
		fetch := func(_ context.Context, endpoint string, _ []string, _ []byte, _ []*x509.Certificate) ([]byte, error) {
			switch endpoint {
			case "http://ca.test/base.crl":
				return clearBase, nil
			case "http://ca.test/delta.crl":
				return delta, nil
			default:
				t.Fatalf("unexpected endpoint %s", endpoint)
				return nil, nil
			}
		}
		got, _ := checkCRL(context.Background(), observed, issuer, []string{"http://ca.test"}, nil, now, fetch)
		if got != "revoked" {
			t.Fatalf("discovery returned %q", got)
		}
	})
}
