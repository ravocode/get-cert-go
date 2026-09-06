// Package certs handles fetching and describing remote TLS certificates.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Target is a resolved host:port to connect to.
type Target struct {
	Host string
	Port string
}

// Address returns the host:port string.
func (t Target) Address() string { return net.JoinHostPort(t.Host, t.Port) }

// ParseTarget accepts a URL (https://host[:port]/...) or a bare host[:port]
// and normalizes it to a Target, defaulting to port 443.
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return Target{}, fmt.Errorf("invalid URL %q: %w", raw, err)
		}
		host := u.Hostname()
		if host == "" {
			return Target{}, fmt.Errorf("could not determine host from %q", raw)
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		return Target{Host: host, Port: port}, nil
	}

	if host, port, err := net.SplitHostPort(raw); err == nil {
		return Target{Host: host, Port: port}, nil
	}
	// No explicit port present.
	return Target{Host: raw, Port: "443"}, nil
}

// FetchChain performs a TLS handshake against the target using a "blind trust"
// configuration (verification disabled) so it can retrieve certificates from
// self-signed or otherwise untrusted internal hosts without erroring out. The
// certificates are returned in the order the server presented them, which is
// typically leaf-first.
func FetchChain(t Target, timeout time.Duration) ([]*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conf := &tls.Config{
		// Intentional: we fetch untrusted certs to inspect/import them.
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         t.Host,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", t.Address(), conf)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake with %s failed: %w", t.Address(), err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented by %s", t.Address())
	}
	return recoverChain(state.PeerCertificates), nil
}

// recoverChain keeps the server-presented chain, but when only the leaf is
// present it tries to discover the issuer from AIA or the local trust store so
// the UX can show the CA the user actually needs to trust.
func recoverChain(peer []*x509.Certificate) []*x509.Certificate {
	if len(peer) != 1 {
		return peer
	}

	leaf := peer[0]
	chain := []*x509.Certificate{leaf}
	if leaf.IssuingCertificateURL == nil {
		return chain
	}
	for _, rawURL := range leaf.IssuingCertificateURL {
		if certs, err := fetchIssuerCandidates(rawURL); err == nil && len(certs) > 0 {
			chain = append(chain, certs...)
			break
		}
	}
	return chain
}
