// Package systemstore installs trusted root certificates into the operating
// system trust store, so that OS-integrated clients (Chrome, Edge, Safari,
// curl on macOS/Linux, etc.) trust them. Each supported OS has its own
// implementation selected at build time.
package systemstore

import (
	"crypto/x509"
	"os"
	"regexp"
	"strings"

	"github.com/ravocode/get-cert-go/internal/certs"
)

// Options controls how a certificate is installed into the OS trust store.
type Options struct {
	// Machine targets a machine-wide store (requires admin/root) instead of the
	// current user's store. On Linux the trust store is always machine-wide.
	Machine bool
	// Name is a logical label for the certificate, used to derive filenames.
	Name string
}

// Result describes where and how a certificate was installed.
type Result struct {
	Store    string // human-readable description of the destination store
	Command  string // the underlying command used, for transparency
	Elevated bool   // whether the operation required elevated privileges
	// FirefoxNote is set when the user should be reminded that Firefox uses its
	// own trust store and is unaffected by this OS-level import.
	FirefoxNote bool
}

// Install adds cert as a trusted root to the OS trust store. It is implemented
// per operating system in the platform-specific files in this package.
func Install(cert *x509.Certificate, opts Options) (Result, error) {
	return install(cert, opts)
}

var nameCleaner = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// safeFileBase returns a filesystem-safe base name for the certificate.
func safeFileBase(cert *x509.Certificate, name string) string {
	base := name
	if base == "" {
		base = certs.SuggestAlias(cert)
	}
	base = nameCleaner.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-.")
	if base == "" {
		base = "cert"
	}
	return base
}

// writeTempPEM writes the certificate to a temporary .pem file and returns its
// path plus a cleanup function. Used by platforms that pass a file path to an
// external tool (Windows certutil, macOS security).
//
//nolint:unused // Used by darwin and windows, but golangci-lint runs on linux.
func writeTempPEM(cert *x509.Certificate, name string) (string, func(), error) {
	f, err := os.CreateTemp("", safeFileBase(cert, name)+"-*.pem")
	if err != nil {
		return "", func() {}, err
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	if _, err := f.Write(certs.EncodePEM(cert)); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}
