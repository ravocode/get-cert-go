package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetchIssuerCandidates tries to download issuer certificates from an AIA URL.
// It only returns CA certificates and ignores leaf-only responses.
func fetchIssuerCandidates(rawURL string) ([]*x509.Certificate, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("unsupported issuer URL: %s", rawURL)
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("issuer fetch returned %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, err
	}

	out := make([]*x509.Certificate, 0, len(certs))
	for _, c := range certs {
		if c.IsCA {
			out = append(out, c)
		}
	}
	return out, nil
}
