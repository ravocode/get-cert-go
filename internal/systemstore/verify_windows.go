//go:build windows

package systemstore

import (
	"crypto/x509"
	"fmt"
	"os/exec"
	"strings"
)

// SystemRootPool returns the current user's Windows Root store as a cert pool.
// It uses the PowerShell certificate provider, which exposes the same store
// that `cert import --system` writes to by default (CurrentUser\Root).
func SystemRootPool() (*x509.CertPool, string, error) {
	script := `Get-ChildItem Cert:\CurrentUser\Root | ForEach-Object { [Console]::WriteLine("-----BEGIN CERTIFICATE-----"); [Console]::WriteLine([Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')); [Console]::WriteLine("-----END CERTIFICATE-----") }`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, "", fmt.Errorf("reading Windows Root store: %s", msg)
	}

	pool := x509.NewCertPool()
	// x509.AppendCertsFromPEM tolerates multiple PEM blocks and ignores garbage.
	if !pool.AppendCertsFromPEM(out) {
		return nil, "", fmt.Errorf("reading Windows Root store: no certificates found")
	}
	return pool, `Windows CurrentUser\Root store`, nil
}
