//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestEnrollmentIdentityRealTLSAndWorkspace(t *testing.T) {
	credential := registryFixtureRecord().Credential
	response := `{"id":"11111111-1111-4111-8111-111111111111","agentId":"agent-a","workspaceId":"22222222-2222-4222-8222-222222222222"}`
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "POST" || r.URL.Path != "/api/v1/certops/agent/credential-rotation/identity" || r.Header.Get("Authorization") != "Bearer "+credential {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	binding, err := verifyEnrollmentIdentity(context.Background(), server.URL, ca, credential, "agent-a", "22222222-2222-4222-8222-222222222222")
	if err != nil || binding.ID != "11111111-1111-4111-8111-111111111111" || binding.Origin != server.URL || len(binding.CAHash) != 64 {
		t.Fatal("matching TLS identity rejected")
	}
	response = `{"id":"11111111-1111-4111-8111-111111111111","agentId":"agent-a","workspaceId":"33333333-3333-4333-8333-333333333333"}`
	if binding, err := verifyEnrollmentIdentity(context.Background(), server.URL, ca, credential, "agent-a", "22222222-2222-4222-8222-222222222222"); err == nil || binding != (rotationBinding{}) {
		t.Fatal("workspace substitution accepted")
	}
	response = `{"id":"11111111-1111-4111-8111-111111111111","id":"11111111-1111-4111-8111-111111111111","agentId":"agent-a","workspaceId":"22222222-2222-4222-8222-222222222222"}`
	if _, err := verifyEnrollmentIdentity(context.Background(), server.URL, ca, credential, "agent-a", "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("duplicate identity accepted")
	}
	before := requests
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wrongCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if _, err := verifyEnrollmentIdentity(context.Background(), server.URL, wrongCA, credential, "agent-a", "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("wrong CA accepted")
	}
	if requests != before {
		t.Fatal("untrusted TLS request reached server")
	}
}

// Exercise the same locked transaction body without requiring an elevated
// SYSTEM mutex; the dedicated SYSTEM test covers the real lock separately.
func TestEnrollmentVerifiedTLSBeforeRegistryStage(t *testing.T) {
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() {
		_ = registry.DeleteKey(parent, boundProvisionPendingKey)
		_ = registry.DeleteKey(parent, boundRotationKey)
	})
	credential := registryFixtureRecord().Credential
	workspace := "33333333-3333-4333-8333-333333333333"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "11111111-1111-4111-8111-111111111111", "agentId": "agent-a", "workspaceId": workspace})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := provisionVerifiedBindingLocked(context.Background(), parent, sddl, trusted, server.URL, ca, credential, "agent-a", "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("workspace substitution accepted")
	}
	if err := ensureNoBoundProvisionPending(parent); err != nil {
		t.Fatal("state persisted before authenticated match")
	}
	workspace = "22222222-2222-4222-8222-222222222222"
	if err := provisionVerifiedBindingLocked(context.Background(), parent, sddl, trusted, server.URL, ca, credential, "agent-a", workspace); err != nil {
		t.Fatal(err)
	}
	pending, err := readBoundProvisionPending(parent, trusted, flushCredentialKey)
	if err != nil || pending.Binding.WorkspaceID != workspace || pending.State.Active != credential {
		t.Fatal("verified pending state unavailable")
	}
	if ensureNoBoundProvisionPending(parent) == nil {
		t.Fatal("pending state allowed activation")
	}
}

func TestEnrollmentProvisionWritesOnlyAfterVerifiedTLSIdentity(t *testing.T) {
	if os.Getenv("TT_ENROLLMENT_SYSTEM_TEST") != "1" {
		t.Skip("requires isolated SYSTEM laboratory fixture")
	}
	parent, sddl, trusted, _ := registryFixture(t)
	t.Cleanup(func() {
		_ = registry.DeleteKey(parent, boundRotationKey)
		_ = registry.DeleteKey(parent, boundProvisionPendingKey)
	})
	credential := registryFixtureRecord().Credential
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"id":"11111111-1111-4111-8111-111111111111","agentId":"agent-a","workspaceId":"22222222-2222-4222-8222-222222222222"}`))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := provisionVerifiedBinding(context.Background(), parent, sddl, trusted, server.URL, ca, credential, "agent-a", "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("mismatched workspace accepted")
	}
	if k, err := registry.OpenKey(parent, boundProvisionPendingKey, registry.QUERY_VALUE); err == nil {
		k.Close()
		t.Fatal("state written before identity verification")
	}
	if err := provisionVerifiedBinding(context.Background(), parent, sddl, trusted, server.URL, ca, credential, "agent-a", "22222222-2222-4222-8222-222222222222"); err != nil {
		t.Fatal(err)
	}
	pending, err := readBoundProvisionPending(parent, trusted, flushCredentialKey)
	if err != nil || pending.State.Active != credential {
		t.Fatal("verified pending state unavailable")
	}
	if err := promoteBoundProvision(context.Background(), parent, sddl, trusted, server.URL, ca, credential, "agent-a", "22222222-2222-4222-8222-222222222222"); err != nil {
		t.Fatal(err)
	}
	if err := promoteBoundProvision(context.Background(), parent, sddl, trusted, server.URL, ca, credential, "agent-a", "22222222-2222-4222-8222-222222222222"); err != nil {
		t.Fatal("promotion retry failed")
	}
	if err := promoteBoundProvision(context.Background(), parent, sddl, trusted, server.URL, ca, credential, "agent-a", "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("mismatched promotion retry accepted")
	}
	proof, err := inspectBoundProvisionRecovery(context.Background(), parent, trusted, server.URL, ca, credential, "agent-a", "22222222-2222-4222-8222-222222222222")
	if err != nil || proof != pending.Binding {
		t.Fatal("recovery proof unavailable")
	}
	if proof, err := inspectBoundProvisionRecovery(context.Background(), parent, trusted, server.URL, ca, credential, "agent-a", "33333333-3333-4333-8333-333333333333"); err == nil || proof != (rotationBinding{}) {
		t.Fatal("mismatched recovery proof accepted")
	}
	got, err := boundStartupCredential(context.Background(), parent, trusted, rotationBinding{ID: "11111111-1111-4111-8111-111111111111", AgentID: "agent-a", WorkspaceID: "22222222-2222-4222-8222-222222222222", Origin: server.URL, CAHash: fmt.Sprintf("%x", sha256.Sum256(ca))})
	if err == nil || got != "" {
		t.Fatal("pending marker did not block startup")
	}
}
