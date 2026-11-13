//go:build windows

package verifiedextraction

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This opt-in integration test leaves protected stages quarantined on purpose.
// Run only on a disposable VM that will be destroyed after the test.
func TestNativeInstallerAuthorizationProtocol(t *testing.T) {
	if os.Getenv("TT_REQUIRE_PROTOCOL_NATIVE") != "1" {
		t.Skip("requires disposable elevated Windows host")
	}
	bundle := os.Getenv("TT_PROTOCOL_BUNDLE")
	if !filepath.IsAbs(bundle) {
		t.Fatal("absolute fixture bundle required")
	}
	payload, err := NewPrivateStaging()
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Close()
	scratch, err := NewPrivateStaging()
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	if err := copyProtocolBundle(bundle, payload.Root()); err != nil {
		t.Fatal(err)
	}
	// Use the exact functions from the fixture's installer script. The package
	// and helper binaries are fixtures; no agent service is installed here.
	harness := `$ErrorActionPreference='Stop'
$PackageDir = Split-Path -Parent $PSScriptRoot
$script:NodeExe = Join-Path $PackageDir 'runtime\amd64\node.exe'
$code = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-agent.ps1') -Raw
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($code,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'installer parse failed' }
$names=@('Invoke-PackagedNode','Get-PackageDirectoryIdentity','Assert-UpgradeRecoveryAcl','Assert-ProtectedIntentDirectory','Assert-ProtectedIntentMarker','Assert-AuthorizedLauncherOrNoIntent','Enter-AgentInstallLock')
foreach ($name in $names) {
  $f=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
  if (@($f).Count -ne 1) { throw 'fixture function missing or ambiguous' }
  Invoke-Expression $f[0].Extent.Text
}
$m=Enter-AgentInstallLock
try { Assert-AuthorizedLauncherOrNoIntent } finally { $m.ReleaseMutex(); $m.Dispose() }
`
	script := filepath.Join(payload.Root(), "scripts", "protocol-fixture.ps1")
	if err := os.WriteFile(script, []byte(harness), 0600); err != nil {
		t.Fatal(err)
	}
	if err := payload.LockPayload(); err != nil {
		t.Fatal(err)
	}
	release, err := beginInstallGuard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := payload.beginExecutionIntent(strings.Repeat("a", 64), strings.Repeat("b", 64), "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", defaultIntentIO())
	if err != nil {
		_ = release()
		t.Fatal(err)
	}
	if err := scratch.BeginScratchIntent(intent.ArchiveSHA256, intent.PreviousSCMSHA256, intent.Transaction, intent.Secret); err != nil {
		_ = release()
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := invokeInstaller(context.Background(), script, scratch.Root(), nil, "", intent.Transaction, intent.Secret, nil); err != nil {
		t.Fatalf("authorized candidate refused: %v", err)
	}
	if err := invokeInstaller(context.Background(), script, scratch.Root(), nil, "", intent.Transaction, strings.Repeat("c", 64), nil); err == nil {
		t.Fatal("forged pipe secret accepted")
	}
	if err := payload.Cleanup(); err != ErrExecutionRecoveryPending {
		t.Fatalf("payload not quarantined: %v", err)
	}
	if err := scratch.Cleanup(); err != ErrExecutionRecoveryPending {
		t.Fatalf("scratch not quarantined: %v", err)
	}
}

func copyProtocolBundle(src, dst string) error {
	return filepath.WalkDir(src, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, name)
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("fixture contains symlink")
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("fixture contains nonregular entry")
		}
		in, err := os.Open(name)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
