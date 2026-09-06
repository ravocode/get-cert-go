//go:build windows

package systemstore

import (
	"crypto/x509"
	"fmt"
	"os/exec"
	"strings"
)

// install adds the certificate to the Windows certificate store's "Root"
// (Trusted Root Certification Authorities) container using certutil. By default
// it targets the current user's store, which needs no elevation and is honored
// by Chrome and Edge. With Machine set it targets LocalMachine, which requires
// running as Administrator.
func install(cert *x509.Certificate, opts Options) (Result, error) {
	pemPath, cleanup, err := writeTempPEM(cert, opts.Name)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	args := []string{}
	store := `CurrentUser\Root`
	if opts.Machine {
		store = `LocalMachine\Root`
	} else {
		args = append(args, "-user")
	}
	args = append(args, "-addstore", "-f", "Root", pemPath)

	out, err := exec.Command("certutil", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if opts.Machine && strings.Contains(strings.ToLower(msg), "denied") {
			msg += " (run this command from an elevated / Administrator terminal)"
		}
		if msg == "" {
			msg = err.Error()
		}
		return Result{}, fmt.Errorf("certutil failed: %s", msg)
	}

	return Result{
		Store:       "Windows certificate store (" + store + ")",
		Command:     "certutil " + strings.Join(args, " "),
		Elevated:    opts.Machine,
		FirefoxNote: true,
	}, nil
}
