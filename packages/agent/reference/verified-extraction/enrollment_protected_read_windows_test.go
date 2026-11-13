//go:build windows && registrycredentialexperiment

package verifiedextraction

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"tokentimer-verified-extraction/bootstraplock"
)

func enrollmentReadFixture(t *testing.T, base string) (string, string, bootstraplock.Policy, map[string]bool) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	trusted := map[string]bool{sid: true, "S-1-5-18": true, "S-1-5-32-544": true}
	installer, _, _, err := windows.LookupSID("", "NT SERVICE\\TrustedInstaller")
	if err != nil {
		t.Fatal(err)
	}
	ancestors := map[string]bool{sid: true, "S-1-5-18": true, "S-1-5-32-544": true, installer.String(): true}
	policy := bootstraplock.Policy{Owners: ancestors, Writers: ancestors}
	if base == "" {
		base = t.TempDir()
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, fmt.Sprintf("tt-enrollment-%x", random))
	if err := createRestrictedDirectory(dir, "O:"+sid+"G:"+sid+"D:P(A;OICI;FA;;;"+sid+")"); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "credential")
	t.Cleanup(func() { _ = os.Remove(name); _ = os.Remove(dir) })
	if err := os.WriteFile(name, []byte("test-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	setFileSecurity := func(extra string) {
		sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sG:%sD:P(A;;FA;;;%s)%s", sid, sid, sid, extra))
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setFileSecurity("")
	return dir, name, policy, trusted
}

func TestEnrollmentProtectedRead(t *testing.T) {
	if os.Getenv("TT_ENROLLMENT_SYSTEM_TEST") != "1" {
		t.Skip("requires isolated SYSTEM laboratory fixture")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	dir, name, policy, trusted := enrollmentReadFixture(t, base)
	locks, lockErr := bootstraplock.LockAncestors(dir, policy)
	if lockErr != nil {
		t.Fatalf("ancestor fixture rejected: %v", lockErr)
	}
	locks.Close()
	b, err := readProtectedEnrollmentFile(dir, "credential", policy, trusted, 128)
	if err != nil || string(b) != "test-secret" {
		t.Fatalf("protected read failed: %v", err)
	}
	clear(b)
	if _, err := readProtectedEnrollmentFile(dir, "credential", policy, trusted, 4); err == nil {
		t.Fatal("oversized secret accepted")
	}
	if _, err := readProtectedEnrollmentFile(dir, "../credential", policy, trusted, 128); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := readProtectedEnrollmentFile(dir, "credential", policy, nil, 128); err == nil {
		t.Fatal("missing reader policy accepted")
	}
	if _, err := readProtectedEnrollmentFile(`\\server\share`, "credential", policy, trusted, 128); err == nil {
		t.Fatal("UNC path accepted")
	}
	writer, err := windows.CreateFile(windows.StringToUTF16Ptr(name), windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("writer fixture unavailable: %v", err)
	}
	if _, err := readProtectedEnrollmentFile(dir, "credential", policy, trusted, 128); err == nil {
		windows.CloseHandle(writer)
		t.Fatal("pre-existing writer accepted")
	}
	windows.CloseHandle(writer)
	b, err = readProtectedEnrollmentFileWithHook(dir, "credential", policy, trusted, 128, func() error {
		replacement := filepath.Join(dir, "replacement")
		if os.Rename(name, replacement) == nil {
			_ = os.Rename(replacement, name)
			return fmt.Errorf("file replacement succeeded")
		}
		if os.Rename(dir, dir+"-moved") == nil {
			_ = os.Rename(dir+"-moved", dir)
			return fmt.Errorf("directory replacement succeeded")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("replacement test failed: %v", err)
	}
	clear(b)
	junction := dir + "-link"
	if err := os.Symlink(dir, junction); err != nil {
		t.Fatalf("reparse fixture unavailable: %v", err)
	}
	defer os.Remove(junction)
	if _, err := readProtectedEnrollmentFile(junction, "credential", policy, trusted, 128); err == nil {
		t.Fatal("reparse parent accepted")
	}
	unsafeDir := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafeDir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(unsafeDir)
	unsafeFile := filepath.Join(unsafeDir, "credential")
	if err := os.WriteFile(unsafeFile, []byte("test-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(unsafeFile)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FW;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(unsafeDir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedEnrollmentFile(unsafeDir, "credential", policy, trusted, 128); err == nil {
		t.Fatal("untrusted parent accepted")
	}
	link := filepath.Join(dir, "another-link")
	if err := os.Link(name, link); err != nil {
		t.Fatalf("hardlink fixture unavailable: %v", err)
	}
	defer os.Remove(link)
	if _, err := readProtectedEnrollmentFile(dir, "credential", policy, trusted, 128); err == nil {
		t.Fatal("hardlinked file accepted")
	}
}

func TestEnrollmentPrivateReadersRejectUntrustedACE(t *testing.T) {
	dir, name, _, trusted := enrollmentReadFixture(t, "")
	_ = dir
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(name), windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEnrollmentPrivateReaders(h, trusted); err != nil {
		windows.CloseHandle(h)
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "G:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	h, err = windows.CreateFile(windows.StringToUTF16Ptr(name), windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := validateEnrollmentPrivateReaders(h, trusted); err == nil || strings.Contains(err.Error(), "test-secret") {
		t.Fatal("untrusted reader accepted or secret leaked")
	}
}
