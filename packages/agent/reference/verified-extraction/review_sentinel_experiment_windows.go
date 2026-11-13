//go:build windows && reviewedrecoveryexperiment

package verifiedextraction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"time"
	"tokentimer-verified-extraction/bootstraplock"
	"unsafe"
)

// Independent experimental schema; production release sentinels remain unchanged.
type reviewDeclaration struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Transaction   string                 `json:"transaction"`
	OperatorSID   string                 `json:"operatorSid"`
	ReviewedAt    string                 `json:"reviewedAt"`
	Statement     string                 `json:"statement"`
	Stages        []QuarantineRecord     `json:"stages"`
	Journal       *upgradeJournalBinding `json:"journal,omitempty"`
}

func createReviewSentinel(path, sddl string, policy bootstraplock.Policy, transaction string, records []QuarantineRecord, statement string, binding *upgradeJournalBinding) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return info, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return info, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, &attrs, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return info, fmt.Errorf("create release sentinel: %w", err)
	}
	defer windows.CloseHandle(h)
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return info, fmt.Errorf("invalid release sentinel")
	}
	if err := validateIntentACL(h, &PrivateStaging{policy: policy}); err != nil {
		return info, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return info, fmt.Errorf("operator identity unavailable")
	}
	declaration, err := json.Marshal(reviewDeclaration{SchemaVersion: 1, Transaction: transaction, OperatorSID: user.User.Sid.String(), ReviewedAt: time.Now().UTC().Format(time.RFC3339), Statement: statement, Stages: records, Journal: binding})
	if err != nil {
		return info, err
	}
	if err := defaultIntentIO().write(h, declaration); err != nil {
		return info, err
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		return info, err
	}
	return info, nil
}

func readReviewSentinel(path string, policy bootstraplock.Policy, transaction, statement string) (reviewDeclaration, windows.ByHandleFileInformation, error) {
	var declaration reviewDeclaration
	var info windows.ByHandleFileInformation
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return declaration, info, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return declaration, info, err
	}
	f := os.NewFile(uintptr(h), "review-sentinel")
	if f == nil {
		windows.CloseHandle(h)
		return declaration, info, fmt.Errorf("sentinel handle unavailable")
	}
	defer f.Close()
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 4096 {
		return declaration, info, fmt.Errorf("invalid review sentinel")
	}
	if err := validateIntentACL(h, &PrivateStaging{policy: policy}); err != nil {
		return declaration, info, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) == 0 || len(b) > 4096 {
		return declaration, info, fmt.Errorf("review sentinel read failed")
	}
	check := json.NewDecoder(bytes.NewReader(b))
	if err := checkJSONValue(check, 0); err != nil {
		return declaration, info, fmt.Errorf("invalid review sentinel JSON")
	}
	if _, err := check.Token(); err != io.EOF {
		return declaration, info, fmt.Errorf("invalid review sentinel JSON")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&declaration); err != nil {
		return declaration, info, fmt.Errorf("invalid review sentinel schema")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil || declaration.SchemaVersion != 1 || declaration.Transaction != transaction || declaration.OperatorSID != user.User.Sid.String() || declaration.Statement != statement || len(declaration.Stages) != 2 {
		return reviewDeclaration{}, info, fmt.Errorf("review sentinel identity or transaction rejected")
	}
	if statement == "operator-reviewed-external-actor-risk" && declaration.Journal != nil {
		return reviewDeclaration{}, info, fmt.Errorf("unexpected journal binding")
	}
	if _, err := time.Parse(time.RFC3339, declaration.ReviewedAt); err != nil {
		return reviewDeclaration{}, info, fmt.Errorf("invalid review timestamp")
	}
	return declaration, info, nil
}
