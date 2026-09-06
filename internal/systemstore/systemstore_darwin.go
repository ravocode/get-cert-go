//go:build darwin

package systemstore

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// install adds the certificate to a macOS keychain and marks it as a trusted
// root using the "security" tool. By default it targets the user's login
// keychain (no sudo). With Machine set it targets the System keychain, which
// requires administrative privileges.
func install(cert *x509.Certificate, opts Options) (Result, error) {
	pemPath, cleanup, err := writeTempPEM(cert, opts.Name)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	var args []string
	var store string
	if opts.Machine {
		args = []string{"add-trusted-cert", "-d", "-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain", pemPath}
		store = "System keychain"
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return Result{}, err
		}
		login := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
		args = []string{"add-trusted-cert", "-r", "trustRoot", "-k", login, pemPath}
		store = "login keychain"
	}

	out, err := exec.Command("security", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return Result{}, fmt.Errorf("security add-trusted-cert failed: %s", msg)
	}

	return Result{
		Store:       "macOS " + store,
		Command:     "security " + strings.Join(args, " "),
		Elevated:    opts.Machine,
		FirefoxNote: true,
	}, nil
}
