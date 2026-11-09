package main

import (
	"context"
	"crypto/x509"
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
}
type response struct {
	Verdict     string     `json:"verdict"`
	ChainStatus string     `json:"chainStatus"`
	CheckedAt   time.Time  `json:"checkedAt"`
	ValidUntil  *time.Time `json:"validUntil,omitempty"`
	Detail      string     `json:"detail,omitempty"`
}

func parseCertificate(input string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(input))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("invalid public certificate")
	}
	return x509.ParseCertificate(block.Bytes)
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
	if len(chains) != 1 {
		out.Detail = "multiple validated chains require disambiguation"
		return write()
	}
	out.ChainStatus = "valid"
	result := revocation.CheckChain(context.Background(), chains[0], req.AllowedOrigins, roots, now)
	out.Verdict = result.Verdict
	out.Detail = result.Detail
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
