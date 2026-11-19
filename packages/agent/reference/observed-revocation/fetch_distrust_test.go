package revocation

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusTLSRejectsDistrustedVerifiedChainMembers(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	intermediate := &x509.Certificate{Raw: []byte("intermediate")}
	root := &x509.Certificate{Raw: []byte("root")}
	other := &x509.Certificate{Raw: []byte("other intermediate")}
	chain := []*x509.Certificate{leaf, intermediate, root}
	for _, cert := range chain {
		denied := map[[sha1.Size]byte]bool{sha1.Sum(cert.Raw): true}
		config := statusTLSConfig(x509.NewCertPool(), denied)
		if config.InsecureSkipVerify {
			t.Fatal("normal hostname and chain verification disabled")
		}
		if err := config.VerifyConnection(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain}}); err == nil {
			t.Fatal("accepted distrusted responder chain")
		}
	}
	config := statusTLSConfig(x509.NewCertPool(), map[[sha1.Size]byte]bool{sha1.Sum(intermediate.Raw): true})
	if err := config.VerifyConnection(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain, {leaf, other, root}}}); err != nil {
		t.Fatalf("clean alternate chain rejected: %v", err)
	}
	if err := config.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("accepted unverified responder")
	}
}

func TestStatusTLSHandshakeEnforcesDistrustAndHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	cert := server.Certificate()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	request := func(config *tls.Config) error {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
		response, err := client.Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		client.CloseIdleConnections()
		return err
	}
	if err := request(statusTLSConfig(pool, nil)); err != nil {
		t.Fatalf("trusted responder rejected: %v", err)
	}
	if err := request(statusTLSConfig(pool, map[[sha1.Size]byte]bool{sha1.Sum(cert.Raw): true})); err == nil {
		t.Fatal("distrusted responder accepted")
	}
	wrongHost := statusTLSConfig(pool, nil)
	wrongHost.ServerName = "wrong.example"
	if err := request(wrongHost); err == nil {
		t.Fatal("incorrect responder hostname accepted")
	}
}
