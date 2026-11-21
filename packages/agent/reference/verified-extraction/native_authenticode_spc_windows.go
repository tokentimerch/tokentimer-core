//go:build windows

package verifiedextraction

import (
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"os"
)

// experimentalSpcSHA256 enforces SHA-256 on the signed PE digest itself,
// separately from the CMS SignerInfo digest. WinVerifyTrust must verify the
// same locked file and the same unique primary WIN_CERTIFICATE afterwards.
func experimentalSpcSHA256(file *os.File) error {
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() > 512<<20 {
		return fmt.Errorf("invalid signed file size")
	}
	p, err := pe.NewFile(file)
	if err != nil {
		return fmt.Errorf("invalid PE image")
	}
	defer p.Close()
	var dir pe.DataDirectory
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dir = h.DataDirectory[4]
	case *pe.OptionalHeader64:
		dir = h.DataDirectory[4]
	default:
		return fmt.Errorf("unsupported PE header")
	}
	if dir.VirtualAddress == 0 || dir.Size < 8 || dir.Size > 16<<20 || uint64(dir.VirtualAddress)+uint64(dir.Size) > uint64(stat.Size()) {
		return fmt.Errorf("invalid PE security directory")
	}
	raw := make([]byte, int(dir.Size))
	if _, err := file.ReadAt(raw, int64(dir.VirtualAddress)); err != nil {
		return err
	}
	length := binary.LittleEndian.Uint32(raw[:4])
	revision := binary.LittleEndian.Uint16(raw[4:6])
	kind := binary.LittleEndian.Uint16(raw[6:8])
	if length < 8 || length > dir.Size || revision != 0x0200 || kind != 0x0002 || (length+7)&^uint32(7) != dir.Size {
		return fmt.Errorf("ambiguous PE signature entries")
	}
	for _, b := range raw[length:] {
		if b != 0 {
			return fmt.Errorf("invalid PE signature padding")
		}
	}
	return spcCMSHasSHA256(raw[8:length])
}

func spcCMSHasSHA256(encoded []byte) error {
	outer, padding, err := takeDER(encoded)
	if err != nil || !isDER(outer, 0, 16, true) || len(padding) > 7 {
		return fmt.Errorf("invalid Authenticode CMS")
	}
	for _, b := range padding {
		if b != 0 {
			return fmt.Errorf("invalid Authenticode CMS padding")
		}
	}
	rest, err := requireOID(outer.Bytes, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})
	if err != nil {
		return err
	}
	explicit, err := onlyDER(rest)
	if err != nil || !isDER(explicit, 2, 0, true) {
		return fmt.Errorf("invalid signed wrapper")
	}
	signed, err := onlyDER(explicit.Bytes)
	if err != nil || !isDER(signed, 0, 16, true) {
		return fmt.Errorf("invalid signed data")
	}
	version, rest, err := takeDER(signed.Bytes)
	if err != nil || !isDER(version, 0, 2, false) {
		return fmt.Errorf("invalid signed version")
	}
	digests, rest, err := takeDER(rest)
	if err != nil || !isDER(digests, 0, 17, true) {
		return fmt.Errorf("invalid signed digest set")
	}
	content, _, err := takeDER(rest)
	if err != nil || !isDER(content, 0, 16, true) {
		return fmt.Errorf("invalid indirect data wrapper")
	}
	spc, err := requireOID(content.Bytes, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4})
	if err != nil {
		return err
	}
	wrapper, err := onlyDER(spc)
	if err != nil || !isDER(wrapper, 2, 0, true) {
		return fmt.Errorf("missing indirect data")
	}
	indirect, err := onlyDER(wrapper.Bytes)
	if err != nil {
		return err
	}
	if isDER(indirect, 0, 4, false) {
		indirect, err = onlyDER(indirect.Bytes)
		if err != nil {
			return err
		}
	}
	if !isDER(indirect, 0, 16, true) {
		return fmt.Errorf("invalid indirect data")
	}
	attribute, remainder, err := takeDER(indirect.Bytes)
	if err != nil || !isDER(attribute, 0, 16, true) {
		return fmt.Errorf("invalid indirect data attribute")
	}
	digestInfo, err := onlyDER(remainder)
	if err != nil || !isDER(digestInfo, 0, 16, true) {
		return fmt.Errorf("invalid file digest")
	}
	algorithm, remainder, err := takeDER(digestInfo.Bytes)
	if err != nil {
		return err
	}
	if err := requireSHA256Algorithm(algorithm); err != nil {
		return fmt.Errorf("file digest is not SHA-256: %w", err)
	}
	value, err := onlyDER(remainder)
	if err != nil || !isDER(value, 0, 4, false) || len(value.Bytes) != 32 {
		return fmt.Errorf("invalid SHA-256 file digest")
	}
	return nil
}
