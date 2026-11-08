package revocation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// This optional test uses a caller-selected private interface because the
// production SSRF policy intentionally refuses loopback destinations.
func TestNetworkCRLAndOCSP(t *testing.T) {
	ip := os.Getenv("CERTOPS_REVOCATION_TEST_IP")
	if ip == "" {
		t.Skip("set CERTOPS_REVOCATION_TEST_IP to a private test interface")
	}
	parsed := net.ParseIP(ip)
	linuxOnly := os.Getenv("CERTOPS_REVOCATION_TEST_LINUX_HELPER") != "" && os.Getenv("CERTOPS_REVOCATION_TEST_HELPER") == ""
	if parsed == nil || (!parsed.IsPrivate() && !(linuxOnly && parsed.IsLoopback())) {
		t.Fatal("test interface must be a private IP")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.RWMutex
	responses := make(map[string][]byte)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		data, ok := responses[r.URL.Path]
		mu.RUnlock()
		if !ok {
			http.Error(w, "offline", 503)
			return
		}
		_, _ = w.Write(data)
	}), ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	origin := "http://" + listener.Addr().String()
	if linuxOnly {
		origin = "http://" + net.JoinHostPort("host.docker.internal", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	}
	now := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	makeKey := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	rootKey, interKey, leafKey := makeKey(), makeKey(), makeKey()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{1}}
	makeCert := func(template, parent *x509.Certificate, key *ecdsa.PrivateKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, e := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if e != nil {
			t.Fatal(e)
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		return cert
	}
	root := makeCert(rootTemplate, rootTemplate, rootKey, rootKey)
	interTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test issuing CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{2}, CRLDistributionPoints: []string{origin + "/root.crl"}}
	inter := makeCert(interTemplate, root, interKey, rootKey)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "test leaf"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), CRLDistributionPoints: []string{origin + "/inter.crl"}, OCSPServer: []string{origin + "/ocsp"}}
	leaf := makeCert(leafTemplate, inter, leafKey, interKey)
	chains, err := VerifyChain(leaf, []*x509.Certificate{inter}, []*x509.Certificate{root}, now)
	if err != nil || len(chains) != 1 {
		t.Fatalf("chain: %v", err)
	}
	makeCRL := func(issuer *x509.Certificate, key *ecdsa.PrivateKey, serial *big.Int, until time.Time) []byte {
		list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: until}
		if serial != nil {
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: serial, RevocationTime: now.Add(-time.Minute)}}
		}
		der, e := x509.CreateRevocationList(rand.Reader, list, issuer, key)
		if e != nil {
			t.Fatal(e)
		}
		return der
	}
	set := func(k string, v []byte) {
		mu.Lock()
		if v == nil {
			delete(responses, k)
		} else {
			responses[k] = v
		}
		mu.Unlock()
	}
	type scanBatch struct {
		Scenario string          `json:"scenario"`
		Verdict  string          `json:"verdict"`
		Items    json.RawMessage `json:"items"`
	}
	var batches []scanBatch
	check := func(scenario, want string) {
		t.Helper()
		captured := false
		if !linuxOnly {
			// Each probe can launch an agent and database, so the response may be
			// produced well after fixture creation. Verify it at the current time.
			got := CheckChain(context.Background(), chains[0], []string{origin}, []*x509.Certificate{root}, time.Now().UTC())
			if got.Verdict != want {
				t.Fatalf("got %+v, want %s", got, want)
			}
		}
		runHelper := func(cmd *exec.Cmd) {
			encode := func(cert *x509.Certificate) string {
				return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			}
			input, e := json.Marshal(map[string]interface{}{"leaf": encode(leaf), "intermediates": []string{encode(inter)}, "roots": []string{encode(root)}, "allowedOrigins": []string{origin}})
			if e != nil {
				t.Fatal(e)
			}
			cmd.Stdin = bytes.NewReader(input)
			out, e := cmd.Output()
			if e != nil {
				t.Fatalf("helper execution: %v", e)
			}
			var decoded struct {
				Verdict string `json:"verdict"`
			}
			if e := json.Unmarshal(out, &decoded); e != nil || decoded.Verdict != want {
				t.Fatalf("helper result %q: %v (want %s)", out, e, want)
			}
		}
		if helper := os.Getenv("CERTOPS_REVOCATION_TEST_HELPER"); helper != "" {
			runHelper(exec.Command(helper))
		}
		if helper := os.Getenv("CERTOPS_REVOCATION_TEST_LINUX_HELPER"); helper != "" {
			runHelper(exec.Command("docker", "run", "--rm", "-i", "-v", helper+":/observed-revocation:ro", "--entrypoint", "sh", "node:24-alpine", "-c", "cp /observed-revocation /tmp/observed && chmod 755 /tmp/observed && exec /tmp/observed"))
		}
		if os.Getenv("CERTOPS_REVOCATION_TEST_AGENT_PROBE") == "1" {
			encode := func(cert *x509.Certificate) string {
				return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			}
			runAgent := func(cmd *exec.Cmd, helper string) {
				input, e := json.Marshal(map[string]string{"leaf": encode(leaf), "intermediate": encode(inter), "root": encode(root), "origin": origin, "expected": want, "helperPath": helper})
				if e != nil {
					t.Fatal(e)
				}
				cmd.Stdin = bytes.NewReader(input)
				output, e := cmd.CombinedOutput()
				if e != nil {
					t.Fatalf("agent scan: %v: %s", e, output)
				}
				if !captured && os.Getenv("CERTOPS_REVOCATION_TEST_DB_PROBE") == "1" {
					if !json.Valid(output) {
						t.Fatalf("invalid agent JSON for %s", scenario)
					}
					batches = append(batches, scanBatch{scenario, want, append(json.RawMessage(nil), output...)})
					captured = true
				}
			}
			if helper := os.Getenv("CERTOPS_REVOCATION_TEST_HELPER"); helper != "" {
				runAgent(exec.Command("node", "agent-scan-probe.cjs"), helper)
			}
			if helper := os.Getenv("CERTOPS_REVOCATION_TEST_LINUX_HELPER"); helper != "" {
				agentDir, e := filepath.Abs("../..")
				if e != nil {
					t.Fatal(e)
				}
				runAgent(exec.Command("docker", "run", "--rm", "-i", "-v", agentDir+":/agent:ro", "-v", helper+":/observed-revocation:ro", "--entrypoint", "sh", "node:24-alpine", "-c", "cp /observed-revocation /tmp/observed && chmod 755 /tmp/observed && exec node /agent/reference/observed-revocation/agent-scan-probe.cjs"), "/tmp/observed")
			}
		}
	}
	set("/root.crl", makeCRL(root, rootKey, nil, now.Add(time.Hour)))
	set("/inter.crl", makeCRL(inter, interKey, nil, now.Add(time.Hour)))
	check("good", "good")
	set("/inter.crl", makeCRL(inter, interKey, leaf.SerialNumber, now.Add(time.Hour)))
	check("leaf-crl", "revoked")
	set("/inter.crl", makeCRL(inter, interKey, nil, now.Add(time.Hour)))
	set("/root.crl", makeCRL(root, rootKey, inter.SerialNumber, now.Add(time.Hour)))
	check("issuer-crl", "issuer_revoked")
	set("/root.crl", makeCRL(root, rootKey, nil, now.Add(time.Hour)))
	ocspDER, err := ocsp.CreateResponse(inter, inter, ocsp.Response{Status: ocsp.Revoked, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), RevokedAt: now.Add(-time.Minute)}, interKey)
	if err != nil {
		t.Fatal(err)
	}
	set("/ocsp", ocspDER)
	check("leaf-ocsp", "revoked")
	set("/ocsp", nil)
	set("/inter.crl", makeCRL(inter, interKey, nil, now.Add(-time.Second)))
	check("expired-crl", "unknown")
	set("/inter.crl", nil)
	check("missing-crl", "unknown")
	if os.Getenv("CERTOPS_REVOCATION_TEST_DB_PROBE") == "1" {
		if len(batches) != 6 {
			t.Fatal("database probe requires the agent probe and a configured helper for all six scenarios")
		}
		probe, e := filepath.Abs("../../../../tests/integration/observed-revocation-agent-probe.cjs")
		if e != nil {
			t.Fatal(e)
		}
		input, e := json.Marshal(batches)
		if e != nil {
			t.Fatal(e)
		}
		persist := exec.Command("node", probe)
		persist.Stdin = bytes.NewReader(input)
		if result, e := persist.CombinedOutput(); e != nil {
			t.Fatalf("agent to console persistence: %v: %s", e, result)
		}
	}
	if _, err := FetchPublicStatus(context.Background(), origin+"/root.crl", nil, nil, []*x509.Certificate{root}); err == nil {
		t.Fatal(fmt.Errorf("unapproved origin accepted"))
	}
}
