//go:build windows

package verifiedextraction

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the real PowerShell guard and inherited pipe on an ordinary Windows
// host. ACL checks are isolated in native staging tests; this fixture verifies
// selection of both intent files and the actual secret handshake.
func TestInstallerAuthorizationAcceptsBothIntentPaths(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "TokenTimer-Staging-"+strings.Repeat("a", 32))
	scratch := filepath.Join(root, "TokenTimer-Staging-"+strings.Repeat("b", 32))
	for _, dir := range []string{payload, scratch} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	transaction, secret := strings.Repeat("c", 32), strings.Repeat("d", 64)
	for _, dir := range []string{payload, scratch} {
		record := map[string]any{"schemaVersion": 1, "phase": "execution-intent", "stageName": filepath.Base(dir), "secret": secret, "transaction": transaction, "archiveSha256": strings.Repeat("e", 64), "volume": 1, "indexHigh": 0, "indexLow": 1}
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir+".intent", data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	installer, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install-agent.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	harness := fmt.Sprintf(`$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('%s',[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'installer parse failed' }
$f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-AuthorizedLauncherOrNoIntent'},$true))
if ($f.Count -ne 1) { throw 'authorization gate missing' }
$body=$f[0].Extent.Text.Replace('[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)', "'%s'")
Invoke-Expression $body
function Assert-ProtectedIntentDirectory { param($Directory) }
function Assert-ProtectedIntentMarker { param($Path) }
$PackageDir='%s'
Assert-AuthorizedLauncherOrNoIntent
if ($script:AuthorizedLauncherTransaction -cne '%s') { throw 'transaction not authenticated' }
`, quote(installer), quote(root), quote(payload), transaction)
	script := filepath.Join(root, "guard-fixture.ps1")
	if err := os.WriteFile(script, []byte(harness), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := invokeInstaller(ctx, script, scratch, nil, "", transaction, secret); err != nil {
		t.Fatalf("two matching intent paths and inherited secret should be accepted: %v", err)
	}
	if err := invokeInstaller(ctx, script, scratch, nil, "", transaction, strings.Repeat("f", 64)); err == nil {
		t.Fatal("incorrect inherited secret was accepted")
	}
}

func TestPackageDirectoryIdentityUnderLauncherJob(t *testing.T) {
	node, err := exec.LookPath("node.exe")
	if err != nil {
		t.Skip("Node not installed on test host")
	}
	// The launcher must supply its own safe executable extensions instead of
	// trusting or omitting the caller's environment.
	t.Setenv("PATHEXT", ".UNTRUSTED")
	root := t.TempDir()
	installer, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install-agent.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	harness := fmt.Sprintf(`Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:NodeExe='%s'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('%s',[ref]$tokens,[ref]$errors)
$f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-PackageDirectoryIdentity'},$true))
if ($errors.Count -or $f.Count -ne 1) { throw 'identity function unavailable' }
Invoke-Expression $f[0].Extent.Text
$id=Get-PackageDirectoryIdentity -Directory '%s'
if ($id -notmatch '^\d+:[1-9]\d*$') { throw 'invalid identity' }
`, quote(node), quote(installer), quote(root))
	script := filepath.Join(root, "identity.ps1")
	if err := os.WriteFile(script, []byte(harness), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := invokeInstaller(ctx, script, root, nil, "", strings.Repeat("a", 32), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
}
