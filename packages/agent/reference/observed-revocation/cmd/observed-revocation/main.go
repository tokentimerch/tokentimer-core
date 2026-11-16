package main

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	revocation "tokentimer-observed-revocation"
)

type request struct {
	Leaf                string   `json:"leaf"`
	Intermediates       []string `json:"intermediates"`
	Roots               []string `json:"roots"`
	SystemRoots         []string `json:"systemRoots"`
	SystemIntermediates []string `json:"systemIntermediates"`
	AllowedOrigins      []string `json:"allowedOrigins"`
	DeniedFingerprints  []string `json:"deniedFingerprints"`
}
type response struct {
	Verdict                        string     `json:"verdict"`
	ChainStatus                    string     `json:"chainStatus"`
	CheckedAt                      time.Time  `json:"checkedAt"`
	ValidUntil                     *time.Time `json:"validUntil,omitempty"`
	Detail                         string     `json:"detail,omitempty"`
	RevokedIssuerFingerprintSha256 string     `json:"revokedIssuerFingerprintSha256,omitempty"`
}

func parseCertificate(input string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(input))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("invalid public certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func statusTLSRoots(roots []*x509.Certificate, denied map[[sha1.Size]byte]bool) []*x509.Certificate {
	var allowed []*x509.Certificate
	for _, root := range roots {
		if !denied[sha1.Sum(root.Raw)] {
			allowed = append(allowed, root)
		}
	}
	return allowed
}

func run(r io.Reader, w io.Writer, now time.Time) error {
	var req request
	decoder := json.NewDecoder(io.LimitReader(r, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected trailing input")
	}
	out := response{Verdict: "unknown", ChainStatus: "unknown", CheckedAt: now}
	write := func() error { return json.NewEncoder(w).Encode(out) }
	leaf, err := parseCertificate(req.Leaf)
	if err != nil {
		out.Detail = "invalid observed certificate"
		return write()
	}
	if len(req.DeniedFingerprints) > 4096 {
		out.Detail = "distrust material exceeds limits"
		return write()
	}
	denied := make(map[[sha1.Size]byte]bool, len(req.DeniedFingerprints))
	for _, value := range req.DeniedFingerprints {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha1.Size || value != hex.EncodeToString(decoded) {
			out.Detail = "invalid distrust material"
			return write()
		}
		var key [sha1.Size]byte
		copy(key[:], decoded)
		denied[key] = true
	}
	if denied[sha1.Sum(leaf.Raw)] {
		out.ChainStatus = "invalid"
		out.Detail = "certificate explicitly distrusted"
		return write()
	}
	if len(req.Roots)+len(req.SystemRoots) > 512 || len(req.Intermediates)+len(req.SystemIntermediates) > 256 || len(req.AllowedOrigins) > 128 {
		out.Detail = "input exceeds limits"
		return write()
	}
	if len(req.Roots)+len(req.SystemRoots) == 0 {
		out.Detail = "trust anchors unavailable"
		return write()
	}
	var roots, intermediates []*x509.Certificate
	for _, encoded := range req.Roots {
		cert, err := parseCertificate(encoded)
		if err != nil {
			out.Detail = "invalid trust anchor"
			return write()
		}
		roots = append(roots, cert)
	}
	// Unsupported certificates in the operating system store must not disable
	// unrelated trust anchors. They never become trusted if parsing fails.
	for _, encoded := range req.SystemRoots {
		if cert, err := parseCertificate(encoded); err == nil {
			roots = append(roots, cert)
		}
	}
	if len(roots) == 0 {
		out.Detail = "trust anchors unavailable"
		return write()
	}
	for _, encoded := range req.Intermediates {
		cert, err := parseCertificate(encoded)
		if err != nil {
			out.Detail = "invalid intermediate"
			return write()
		}
		intermediates = append(intermediates, cert)
	}
	for _, encoded := range req.SystemIntermediates {
		if cert, err := parseCertificate(encoded); err == nil {
			intermediates = append(intermediates, cert)
		}
	}
	chains, err := revocation.VerifyChain(leaf, intermediates, roots, now)
	if err != nil {
		out.ChainStatus = "invalid"
		out.Detail = "certificate chain validation failed"
		return write()
	}
	allowedChains := chains[:0]
	for _, chain := range chains {
		allowed := true
		for _, cert := range chain {
			if denied[sha1.Sum(cert.Raw)] {
				allowed = false
				break
			}
		}
		if allowed {
			allowedChains = append(allowedChains, chain)
		}
	}
	chains = allowedChains
	if len(chains) == 0 {
		out.ChainStatus = "invalid"
		out.Detail = "certificate chain explicitly distrusted"
		return write()
	}
	if len(chains) != 1 {
		out.Detail = "multiple validated chains require disambiguation"
		return write()
	}
	out.ChainStatus = "valid"
	// Distrusted roots must not authorize the HTTPS connection used to fetch
	// status, even when the observed certificate has another valid chain.
	result := revocation.CheckChainWithDistrust(context.Background(), chains[0], req.AllowedOrigins, statusTLSRoots(roots, denied), denied, now)
	out.Verdict = result.Verdict
	out.Detail = result.Detail
	out.RevokedIssuerFingerprintSha256 = result.RevokedIssuerFingerprintSha256
	if !result.ValidUntil.IsZero() {
		out.ValidUntil = &result.ValidUntil
	}
	return write()
}

func main() {
	if err := run(os.Stdin, os.Stdout, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "invalid verification request")
		os.Exit(1)
	}
}
