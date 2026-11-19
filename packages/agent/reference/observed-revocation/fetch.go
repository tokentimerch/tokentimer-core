package revocation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// FetchPublicStatus allows only explicitly configured origins. DNS is resolved
// once, checked, and the connection is pinned to that result. Redirects and
// environment proxies are disabled. Signatures must be verified separately.
func FetchPublicStatus(ctx context.Context, raw string, allowedOrigins []string, post []byte, tlsRoots []*x509.Certificate) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid responder URL")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	origin := strings.ToLower(u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port))
	allowed := false
	for _, candidate := range allowedOrigins {
		a, e := url.Parse(candidate)
		if e != nil || a.User != nil || a.Hostname() == "" || a.RawQuery != "" || a.Fragment != "" || (a.Path != "" && a.Path != "/") {
			continue
		}
		ap := a.Port()
		if ap == "" {
			if a.Scheme == "https" {
				ap = "443"
			} else if a.Scheme == "http" {
				ap = "80"
			}
		}
		if strings.ToLower(a.Scheme+"://"+net.JoinHostPort(a.Hostname(), ap)) == origin {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("responder origin not allowed")
	}
	// A non-system pool prevents platform chain builders from fetching AIA or
	// revocation URLs outside this module's egress policy during TLS setup.
	var pool *x509.CertPool
	if u.Scheme == "https" {
		if len(tlsRoots) == 0 {
			return nil, fmt.Errorf("HTTPS trust anchors unavailable")
		}
		pool = x509.NewCertPool()
		for _, root := range tlsRoots {
			if root == nil {
				return nil, fmt.Errorf("invalid HTTPS trust anchor")
			}
			pool.AddCert(root)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("responder DNS unavailable")
	}
	for _, ip := range ips {
		if !safeResponderIP(ip) {
			return nil, fmt.Errorf("responder resolves to denied address")
		}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		var last error
		for _, ip := range ips {
			var d net.Dialer
			c, e := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return c, nil
			}
			last = e
		}
		return nil, last
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	method := http.MethodGet
	var body io.Reader
	if post != nil {
		method = http.MethodPost
		body = bytes.NewReader(post)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if post != nil {
		req.Header.Set("Content-Type", "application/ocsp-request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("responder returned HTTP %d", resp.StatusCode)
	}
	const maxBytes = 8 << 20
	result, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(result) > maxBytes {
		return nil, fmt.Errorf("response too large")
	}
	return result, nil
}

func safeResponderIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() && ip.String() != "255.255.255.255"
}
