//go:build windows

package bootstraplock

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"syscall"
	"testing"
)

func TestHandlePolicyChecksRealWindowsDACL(t *testing.T) {
	base := t.TempDir()
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := tokenUser.User.Sid.String()
	policy := Policy{Owners: map[string]bool{sid: true}, Writers: map[string]bool{sid: true}}
	setDACL := func(sddl string) {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(base, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			tokenUser.User.Sid, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setDACL(fmt.Sprintf("D:P(A;;FA;;;%s)", sid))
	file, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := policy.ValidateHandle(syscall.Handle(file.Fd()), false); err != nil {
		t.Fatalf("protected handle rejected: %v", err)
	}
	setDACL(fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FW;;;WD)", sid))
	if err := policy.ValidateHandle(syscall.Handle(file.Fd()), false); err == nil {
		t.Fatal("untrusted write access was accepted")
	}
}

func TestSecurityDescriptorPolicy(t *testing.T) {
	policy := Policy{Owners: map[string]bool{"S-1-5-18": true}, Writers: map[string]bool{"S-1-5-18": true}}
	tests := []struct {
		name, sddl       string
		ancestor, wantOK bool
	}{
		{"protected payload", "O:SYD:(A;;FA;;;SY)(A;;FR;;;WD)", false, true},
		{"untrusted owner", "O:WDD:(A;;FA;;;SY)", false, false},
		{"null dacl", "O:SYD:NO_ACCESS_CONTROL", false, false},
		{"untrusted create in payload", "O:SYD:(A;;FA;;;SY)(A;;0x00000002;;;WD)", false, false},
		{"untrusted create subdirectory in direct parent", "O:SYD:(A;;FA;;;SY)(A;;0x00000004;;;WD)", false, false},
		{"higher ancestor create subdirectory only", "O:SYD:(A;;FA;;;SY)(A;;0x00000004;;;WD)", true, true},
		{"untrusted delete child on ancestor", "O:SYD:(A;;FA;;;SY)(A;;0x00000040;;;WD)", true, false},
		{"untrusted write attributes on ancestor", "O:SYD:(A;;FA;;;SY)(A;;0x00000100;;;WD)", true, false},
		{"untrusted write data on ancestor", "O:SYD:(A;;FA;;;SY)(A;;0x00000002;;;WD)", true, false},
		{"untrusted owner change", "O:SYD:(A;;FA;;;SY)(A;;0x00080000;;;WD)", true, false},
		{"untrusted generic write on ancestor", "O:SYD:(A;;FA;;;SY)(A;;GW;;;WD)", true, false},
		{"read only", "O:SYD:(A;;FA;;;SY)(A;;FR;;;WD)", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatalf("invalid SDDL fixture: %v", err)
			}
			err = policy.validateDescriptor(sd, tc.ancestor)
			if (err == nil) != tc.wantOK {
				t.Fatalf("got %v; wantOK=%v", err, tc.wantOK)
			}
		})
	}
}
