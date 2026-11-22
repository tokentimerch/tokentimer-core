//go:build windows && azurecmsqualify

package verifiedextraction

// This disposable end-to-end fixture does not qualify Azure, a launcher,
// filesystem handoff, or any release; publisher roots never leave memory.
import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExperimentalSignedInventoryAndArtifactBinding(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("Python required for artifact-binding fixture")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	validator := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "scripts", "windows-release-artifact-binding.py"))
	payload := []byte("isolated fixture content")
	var compressed bytes.Buffer
	zipped := gzip.NewWriter(&compressed)
	archive := tar.NewWriter(zipped)
	if err := archive.WriteHeader(&tar.Header{Name: "package/fixture.js", Mode: 0600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipped.Close(); err != nil {
		t.Fatal(err)
	}
	archiveBytes := compressed.Bytes()
	sbom := []byte(`{"fixture":"not-a-real-sbom"}`)
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	commit := strings.Repeat("a", 40)
	archiveName := "tokentimer-agent-1.2.3-windows-amd64.tgz"
	sbomName := "fixture.cdx.json"
	inventory, err := json.Marshal(map[string]any{"schemaVersion": 1, "sourceCommit": commit, "version": "1.2.3", "architecture": "amd64",
		"archive": map[string]string{"name": archiveName, "sha256": hash(archiveBytes)}, "sbom": map[string]string{"name": sbomName, "sha256": hash(sbom)},
		"files": []map[string]any{{"path": "package/fixture.js", "sha256": hash(payload), "size": len(payload)}}})
	if err != nil {
		t.Fatal(err)
	}
	publisher := testIdentityCreate(t, false)
	tsa := testIdentityCreate(t, true)
	_, signature := testCMS(t, inventory, testDataOID, publisher, nil, false)
	imprint := sha256.Sum256(signature)
	algorithm := testSeq(t, testOID(t, 2, 16, 840, 1, 101, 3, 4, 2, 1), []byte{5, 0})
	clock, err := asn1.MarshalWithParams(time.Now().UTC().Truncate(time.Second), "generalized")
	if err != nil {
		t.Fatal(err)
	}
	info := testSeq(t, testDER(t, 1), testOID(t, 1, 2, 3, 4), testSeq(t, algorithm, testDER(t, imprint[:])), testDER(t, 99), clock)
	timestamp, _ := testCMS(t, info, testTSTOID, tsa, nil, true)
	cms, _ := testCMS(t, inventory, testDataOID, publisher, timestamp, false)
	policy := AzureCMSQualificationPolicy{hash(publisher.root), hash(tsa.root), "1.3.6.1.4.1.311.97.123.456.789", hash(inventory)}
	pub := testPrivateEngine(t, publisher.root, testCRL(t, publisher, false))
	ts := testPrivateEngine(t, tsa.root, testCRL(t, tsa, false))
	revoked := testPrivateEngine(t, publisher.root, testCRL(t, publisher, true))
	dir := t.TempDir()
	archivePath := filepath.Join(dir, archiveName)
	sbomPath := filepath.Join(dir, sbomName)
	invPath := filepath.Join(dir, "inventory.json")
	check := func(signed, inv, arc, bom []byte, chain experimentalChainContext) error {
		if err := qualifyAzureCMSWithContexts(signed, inv, policy, chain, ts); err != nil {
			return err
		}
		for path, data := range map[string][]byte{archivePath: arc, sbomPath: bom, invPath: inv} {
			if err := os.WriteFile(path, data, 0600); err != nil {
				return err
			}
		}
		out, err := exec.Command(python, validator, "--archive", archivePath, "--archive-sha256", hash(archiveBytes), "--sbom", sbomPath, "--inventory", invPath, "--version", "1.2.3", "--architecture", "amd64", "--source-commit", commit).Output()
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(out)) != hash(inv) {
			return fmt.Errorf("validator inventory digest mismatch")
		}
		return nil
	}
	if err := check(cms, inventory, archiveBytes, sbom, pub); err != nil {
		t.Fatalf("fixture binding failed: %v", err)
	}
	tamperedSignature := bytes.Clone(cms)
	position := bytes.Index(tamperedSignature, signature)
	if position < 0 {
		t.Fatal("fixture signature not found")
	}
	tamperedSignature[position] ^= 1
	for _, tc := range []struct {
		name                          string
		cms, inventory, archive, sbom []byte
		chain                         experimentalChainContext
	}{
		{"trailing CMS bytes", append(bytes.Clone(cms), 0), inventory, archiveBytes, sbom, pub},
		{"modified signature", tamperedSignature, inventory, archiveBytes, sbom, pub},
		{"modified inventory", cms, append(bytes.Clone(inventory), ' '), archiveBytes, sbom, pub},
		{"modified archive", cms, inventory, append(bytes.Clone(archiveBytes), 0), sbom, pub},
		{"modified sbom", cms, inventory, archiveBytes, append(bytes.Clone(sbom), ' '), pub},
		{"revoked publisher", cms, inventory, archiveBytes, sbom, revoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := check(tc.cms, tc.inventory, tc.archive, tc.sbom, tc.chain); err == nil {
				t.Fatal("tampered fixture accepted")
			}
		})
	}
}
