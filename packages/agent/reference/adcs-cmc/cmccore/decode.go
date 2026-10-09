// Package cmccore parses CA-signed CMC responses for the AD CS issuer path.
//
// This is a trust boundary: strict DER, 64 KiB bound, no trailing data, and
// the CMS signature must verify against a CA certificate whose public-key
// SHA-256 equals the enrollment snapshot's caKeySha256. See ADR-0014.
package cmccore

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"go.mozilla.org/pkcs7"
)

// MaxResponseBytes is the hard upper bound on a CMC response body.
const MaxResponseBytes = 64 * 1024

// OIDs from RFC 5272 / Microsoft AD CS CMC responses.
var (
	oidCMCStatusInfo = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 7, 1}
	// Microsoft nests the issued-cert hash (21.17) under this control attribute.
	oidMSCMCCertHash = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 10, 1}
	oidMSIssuedCertHash = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 17}
)

const (
	cmcStatusSuccess = 0
	cmcStatusFailed  = 2
	cmcStatusPending = 3
)

// Result is the structured verdict the agent consumes as JSON.
type Result struct {
	Disposition       string  `json:"disposition"` // issued | pending | denied | unknown
	RequestID         *uint32 `json:"requestId,omitempty"`
	CertificateDerB64 string  `json:"certificateDerB64,omitempty"`
	Error             string  `json:"error,omitempty"`
}

// Decode parses and verifies a CMC response. caKeySHA256 is the enrollment
// snapshot pin (hex SHA-256 of the CA SubjectPublicKeyInfo). caCerts are the
// preflight CA certificates used when the response names the signer by
// issuer/serial only (pending and denied responses).
func Decode(response []byte, caKeySHA256 string, caCerts ...*x509.Certificate) (Result, error) {
	if len(response) == 0 {
		return Result{}, fmt.Errorf("empty CMC response")
	}
	if len(response) > MaxResponseBytes {
		return Result{}, fmt.Errorf("CMC response exceeds %d bytes", MaxResponseBytes)
	}
	pin, err := normalizePin(caKeySHA256)
	if err != nil {
		return Result{}, err
	}

	der, err := normalizeDER(response)
	if err != nil {
		return Result{}, err
	}
	if len(der) > MaxResponseBytes {
		return Result{}, fmt.Errorf("CMC response exceeds %d bytes", MaxResponseBytes)
	}
	if err := requireExactDER(der); err != nil {
		return Result{}, err
	}

	sd, err := pkcs7.Parse(der)
	if err != nil {
		return Result{}, fmt.Errorf("CMS SignedData: %w", err)
	}

	if err := verifyCMS(sd, caCerts); err != nil {
		return Result{}, err
	}

	signer := sd.GetOnlySigner()
	if signer == nil {
		signer, err = matchSigner(sd, caCerts)
		if err != nil {
			return Result{}, err
		}
	}
	if spkiSHA256Hex(signer) != pin {
		return Result{}, fmt.Errorf("CMS signer key does not match caKeySha256")
	}

	content := sd.Content
	if len(content) == 0 {
		return Result{}, fmt.Errorf("CMC response has empty content")
	}
	if err := requireExactDER(content); err != nil {
		return Result{}, fmt.Errorf("PKIResponse: %w", err)
	}

	status, requestID, certHash, err := parsePKIResponse(content)
	if err != nil {
		return Result{}, err
	}

	switch status {
	case cmcStatusSuccess:
		leaf := pickIssuedLeaf(sd.Certificates, signer)
		return successResult(leaf, certHash), nil
	case cmcStatusPending:
		if requestID == nil {
			return unknown("pending status without pend token"), nil
		}
		return Result{Disposition: "pending", RequestID: requestID}, nil
	case cmcStatusFailed:
		return Result{Disposition: "denied"}, nil
	default:
		return unknown(fmt.Sprintf("unsupported CMC status %d", status)), nil
	}
}

func unknown(reason string) Result {
	return Result{Disposition: "unknown", Error: reason}
}

func successResult(leaf *x509.Certificate, certHash []byte) Result {
	if leaf == nil {
		return unknown("success status without issued certificate")
	}
	if len(certHash) == 0 {
		return unknown("success status without issued-cert hash attribute")
	}
	sum := sha1.Sum(leaf.Raw)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), hex.EncodeToString(certHash)) {
		return unknown("issued-cert hash attribute does not match certificate")
	}
	return Result{
		Disposition:       "issued",
		CertificateDerB64: base64.StdEncoding.EncodeToString(leaf.Raw),
	}
}

func normalizePin(pin string) (string, error) {
	p := strings.TrimSpace(strings.ToLower(pin))
	if p == "" {
		return "", fmt.Errorf("caKeySha256 is required")
	}
	if len(p) != 64 {
		return "", fmt.Errorf("caKeySha256 must be 64 hex characters")
	}
	if _, err := hex.DecodeString(p); err != nil {
		return "", fmt.Errorf("caKeySha256 must be hex: %w", err)
	}
	return p, nil
}

func normalizeDER(raw []byte) ([]byte, error) {
	trim := bytesTrimSpace(raw)
	if block, rest := pem.Decode(trim); block != nil {
		if len(bytesTrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("trailing data after PEM block")
		}
		return block.Bytes, nil
	}
	// certreq often writes base64 without PEM headers.
	if looksLikeBase64Text(trim) {
		decoded, err := base64.StdEncoding.DecodeString(string(collapseWS(trim)))
		if err == nil && len(decoded) > 0 && decoded[0] == 0x30 {
			return decoded, nil
		}
	}
	return trim, nil
}

func requireExactDER(der []byte) error {
	var rest []byte
	var val asn1.RawValue
	rest, err := asn1.Unmarshal(der, &val)
	if err != nil {
		return fmt.Errorf("malformed DER: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing data after DER value")
	}
	return nil
}

func spkiSHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func pickIssuedLeaf(certs []*x509.Certificate, ca *x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		if c == nil || ca == nil {
			continue
		}
		if c.Equal(ca) {
			continue
		}
		if c.Subject.String() == c.Issuer.String() {
			continue
		}
		return c
	}
	return nil
}

func verifyCMS(sd *pkcs7.PKCS7, caCerts []*x509.Certificate) error {
	if len(sd.Certificates) > 0 {
		if err := sd.Verify(); err == nil {
			return nil
		}
		pool := x509.NewCertPool()
		for _, c := range caCerts {
			if c != nil {
				pool.AddCert(c)
			}
		}
		for _, c := range sd.Certificates {
			pool.AddCert(c)
		}
		if err := sd.VerifyWithChain(pool); err == nil {
			return nil
		}
	}
	if len(caCerts) == 0 {
		return fmt.Errorf("CMS signature verify failed: no signer certificates")
	}
	return verifyWithExternalSigners(sd, caCerts)
}

func matchSigner(sd *pkcs7.PKCS7, caCerts []*x509.Certificate) (*x509.Certificate, error) {
	for _, c := range caCerts {
		if c == nil {
			continue
		}
		if err := verifyWithExternalSigners(sd, []*x509.Certificate{c}); err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("CMS signer certificate not found")
}

func verifyWithExternalSigners(sd *pkcs7.PKCS7, caCerts []*x509.Certificate) error {
	// mozilla/pkcs7 Verify() uses embedded certs. When the bag is empty,
	// temporarily attach candidate CAs and verify.
	orig := sd.Certificates
	defer func() { sd.Certificates = orig }()
	sd.Certificates = append([]*x509.Certificate{}, caCerts...)
	return sd.Verify()
}

// taggedAttribute is bodyPartID + OID + SET OF values (RFC 5272).
type taggedAttribute struct {
	BodyPartID int
	Type       asn1.ObjectIdentifier
	Values     []asn1.RawValue `asn1:"set"`
}

type pkiResponse struct {
	ControlSequence    []taggedAttribute
	CMSSequence        []asn1.RawValue `asn1:"optional"`
	OtherMsgSequence   []asn1.RawValue `asn1:"optional"`
}

func parsePKIResponse(content []byte) (status int, requestID *uint32, certHash []byte, err error) {
	var resp pkiResponse
	rest, err := asn1.Unmarshal(content, &resp)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("PKIResponse: %w", err)
	}
	if len(rest) != 0 {
		return 0, nil, nil, fmt.Errorf("PKIResponse: trailing data")
	}

	var sawStatus bool
	for _, attr := range resp.ControlSequence {
		if attr.Type.Equal(oidCMCStatusInfo) {
			if sawStatus {
				return 0, nil, nil, fmt.Errorf("multiple CMCStatusInfo attributes")
			}
			if len(attr.Values) != 1 {
				return 0, nil, nil, fmt.Errorf("CMCStatusInfo value count %d", len(attr.Values))
			}
			st, rid, err := parseCMCStatusInfo(attr.Values[0].FullBytes)
			if err != nil {
				return 0, nil, nil, err
			}
			status = st
			requestID = rid
			sawStatus = true
			continue
		}
		// PoC responses put 1.3.6.1.4.1.311.21.17 under 1.3.6.1.4.1.311.21.10.1.
		// Also accept a top-level 21.17 attribute if a CA emits that shape.
		if h, ok := extractIssuedCertHash(attr.Values); ok {
			certHash = h
		} else if attr.Type.Equal(oidMSCMCCertHash) || attr.Type.Equal(oidMSIssuedCertHash) {
			return 0, nil, nil, fmt.Errorf("issued-cert hash attribute missing digest")
		}
	}
	if !sawStatus {
		return 0, nil, nil, fmt.Errorf("CMCStatusInfo missing")
	}
	return status, requestID, certHash, nil
}

func parseCMCStatusInfo(der []byte) (status int, requestID *uint32, err error) {
	// CMCStatusInfo ::= SEQUENCE {
	//   cMCStatus INTEGER,
	//   bodyList SEQUENCE OF BodyPartID,
	//   statusString UTF8String OPTIONAL,
	//   otherInfo CHOICE { failInfo INTEGER, pendInfo PendInfo } OPTIONAL
	// }
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || outer.Tag != asn1.TagSequence {
		return 0, nil, fmt.Errorf("CMCStatusInfo: malformed SEQUENCE")
	}
	b := outer.Bytes
	var st int
	b, err = asn1.Unmarshal(b, &st)
	if err != nil {
		return 0, nil, fmt.Errorf("CMCStatusInfo.status: %w", err)
	}
	var bodyList asn1.RawValue
	b, err = asn1.Unmarshal(b, &bodyList)
	if err != nil {
		return 0, nil, fmt.Errorf("CMCStatusInfo.bodyList: %w", err)
	}
	if len(b) == 0 {
		return st, nil, nil
	}
	// optional UTF8String
	var next asn1.RawValue
	nb, err := asn1.Unmarshal(b, &next)
	if err != nil {
		return 0, nil, fmt.Errorf("CMCStatusInfo.optional: %w", err)
	}
	if next.Tag == asn1.TagUTF8String {
		b = nb
		if len(b) == 0 {
			return st, nil, nil
		}
		b, err = asn1.Unmarshal(b, &next)
		if err != nil {
			return 0, nil, fmt.Errorf("CMCStatusInfo.otherInfo: %w", err)
		}
	}
	// pendInfo is SEQUENCE (universal); failInfo is INTEGER.
	if next.Tag == asn1.TagSequence {
		rid, err := parsePendToken(next.Bytes)
		if err != nil {
			return 0, nil, err
		}
		return st, &rid, nil
	}
	return st, nil, nil
}

func parsePendToken(pendInfoBytes []byte) (uint32, error) {
	// PendInfo ::= SEQUENCE { pendToken OCTET STRING, pendTime GeneralizedTime }
	var token []byte
	rest, err := asn1.Unmarshal(pendInfoBytes, &token)
	if err != nil {
		return 0, fmt.Errorf("pendToken: %w", err)
	}
	if len(token) != 4 {
		return 0, fmt.Errorf("pendToken must be 4 bytes, got %d", len(token))
	}
	id := uint32(token[0]) | uint32(token[1])<<8 | uint32(token[2])<<16 | uint32(token[3])<<24
	// consume GeneralizedTime so the SEQUENCE is fully read
	var gt asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &gt)
	if err != nil || len(rest) != 0 {
		return 0, fmt.Errorf("pendTime: malformed")
	}
	return id, nil
}

func extractIssuedCertHash(values []asn1.RawValue) ([]byte, bool) {
	// PoC shape: control attr 1.3.6.1.4.1.311.21.10.1 whose value nests
	// OID 1.3.6.1.4.1.311.21.17 and a 20-byte SHA-1 OCTET STRING.
	for _, v := range values {
		hash, ok := findOctetStringOID(v.FullBytes, oidMSIssuedCertHash)
		if ok && (len(hash) == 20 || len(hash) == 32) {
			return hash, true
		}
		var direct []byte
		if _, err := asn1.Unmarshal(v.Bytes, &direct); err == nil && (len(direct) == 20 || len(direct) == 32) {
			return direct, true
		}
	}
	return nil, false
}

func findOctetStringOID(der []byte, want asn1.ObjectIdentifier) ([]byte, bool) {
	var walk func([]byte) ([]byte, bool)
	walk = func(b []byte) ([]byte, bool) {
		for len(b) > 0 {
			var rv asn1.RawValue
			rest, err := asn1.Unmarshal(b, &rv)
			if err != nil {
				return nil, false
			}
			b = rest
			if rv.Tag == asn1.TagOID {
				var oid asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(rv.FullBytes, &oid); err == nil && oid.Equal(want) {
					// next sibling often SET OF OCTET STRING
					if len(rest) > 0 {
						var set asn1.RawValue
						_, err := asn1.Unmarshal(rest, &set)
						if err == nil && set.IsCompound {
							var oct []byte
							if _, err := asn1.Unmarshal(set.Bytes, &oct); err == nil {
								return oct, true
							}
						}
					}
				}
			}
			if rv.IsCompound {
				if oct, ok := walk(rv.Bytes); ok {
					return oct, true
				}
			}
		}
		return nil, false
	}
	return walk(der)
}

func findFirstOctetString(der []byte, wantLen int) ([]byte, bool) {
	for len(der) > 0 {
		var rv asn1.RawValue
		rest, err := asn1.Unmarshal(der, &rv)
		if err != nil {
			return nil, false
		}
		der = rest
		if rv.Tag == asn1.TagOctetString && len(rv.Bytes) == wantLen {
			return rv.Bytes, true
		}
		if rv.IsCompound {
			if oct, ok := findFirstOctetString(rv.Bytes, wantLen); ok {
				return oct, true
			}
		}
	}
	return nil, false
}

func bytesTrimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

func collapseWS(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return out
}

func looksLikeBase64Text(b []byte) bool {
	if len(b) < 16 || b[0] == 0x30 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t':
		default:
			return false
		}
	}
	return true
}
