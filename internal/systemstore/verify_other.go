//go:build !windows

package systemstore

import (
	"crypto/x509"
	"fmt"
)

// SystemRootPool returns the OS trust store roots as a cert pool for
// verification.
func SystemRootPool() (*x509.CertPool, string, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, "", fmt.Errorf("loading system trust store: %w", err)
	}
	if pool == nil {
		return nil, "", fmt.Errorf("loading system trust store: returned nil pool")
	}
	return pool, "OS system trust store", nil
}
