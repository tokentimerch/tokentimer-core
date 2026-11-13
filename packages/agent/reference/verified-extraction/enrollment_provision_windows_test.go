//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestEnrollmentProtectedFilesTLSAndRegistry(t *testing.T) {
	if os.Getenv("TT_ENROLLMENT_SYSTEM_TEST") != "1" {
		t.Skip("requires isolated SYSTEM laboratory fixture")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	dir, credentialPath, policy, trusted := enrollmentReadFixture(t, base)
	parent, sddl, registryTrusted, _ := registryFixture(t)
	t.Cleanup(func() {
		_ = registry.DeleteKey(parent, boundRotationKey)
		_ = registry.DeleteKey(parent, boundProvisionPendingKey)
	})
	credential := registryFixtureRecord().Credential
	if err := os.WriteFile(credentialPath, []byte(credential), 0600); err != nil {
		t.Fatal(err)
	}
	workspace := "33333333-3333-4333-8333-333333333333"
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer "+credential {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "11111111-1111-4111-8111-111111111111", "agentId": "agent-a", "workspaceId": workspace})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caPath := filepath.Join(dir, "ca-bundle.pem")
	configPath := filepath.Join(dir, "config.json")
	t.Cleanup(func() { _ = os.Remove(configPath); _ = os.Remove(caPath) })
	config, _ := json.Marshal(map[string]string{"agentId": "agent-a", "workspaceId": "22222222-2222-4222-8222-222222222222", "serverUrl": server.URL, "caBundlePath": caPath})
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "G:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{caPath, configPath} {
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	pending := filepath.Join(dir, "registration.pending.json")
	t.Cleanup(func() { _ = os.Remove(pending) })
	if err := os.WriteFile(pending, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := provisionFromProtectedEnrollment(context.Background(), dir, policy, trusted, parent, sddl); err == nil || requests != 0 {
		t.Fatal("pending registration did not block before network")
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if err := provisionFromProtectedEnrollment(context.Background(), dir, policy, trusted, parent, sddl); err == nil {
		t.Fatal("wrong workspace accepted")
	}
	if k, err := registry.OpenKey(parent, boundProvisionPendingKey, registry.QUERY_VALUE); err == nil {
		k.Close()
		t.Fatal("unverified data persisted")
	}
	workspace = "22222222-2222-4222-8222-222222222222"
	if err := provisionFromProtectedEnrollment(context.Background(), dir, policy, trusted, parent, sddl); err != nil {
		t.Fatal(err)
	}
	state, err := readBoundProvisionPending(parent, registryTrusted, flushCredentialKey)
	if err != nil || state.Binding.WorkspaceID != workspace || state.Binding.Origin != server.URL || state.State.Active != credential {
		t.Fatal("verified binding unavailable")
	}
	if err := promoteBoundProvision(context.Background(), parent, sddl, registryTrusted, server.URL, ca, credential, "agent-a", workspace); err != nil {
		t.Fatal(err)
	}
	if got, err := boundStartupCredential(context.Background(), parent, registryTrusted, state.Binding); err == nil || got != "" {
		t.Fatal("pending marker did not block startup")
	}
}
