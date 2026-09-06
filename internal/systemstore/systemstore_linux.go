//go:build linux

package systemstore

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ravocode/get-cert-go/internal/certs"
)

// anchorTarget describes a distro's local CA anchor directory and the command
// used to rebuild the consolidated trust bundle.
type anchorTarget struct {
	dir       string
	updateCmd string
	// ext is the required file extension for anchors in this directory.
	ext string
}

// linuxTargets lists supported anchor locations, most common first.
var linuxTargets = []anchorTarget{
	{dir: "/usr/local/share/ca-certificates", updateCmd: "update-ca-certificates", ext: ".crt"}, // Debian/Ubuntu
	{dir: "/etc/pki/ca-trust/source/anchors", updateCmd: "update-ca-trust", ext: ".crt"},         // RHEL/Fedora/CentOS
	{dir: "/etc/ca-certificates/trust-source/anchors", updateCmd: "update-ca-trust", ext: ".crt"},// Arch
}

// install copies the certificate into the distro's CA anchor directory and runs
// the trust-update command. The Linux system trust store is inherently
// machine-wide and requires root privileges (Options.Machine is ignored).
func install(cert *x509.Certificate, opts Options) (Result, error) {
	target, ok := pickTarget()
	if !ok {
		return Result{}, fmt.Errorf("no supported CA anchor directory found; expected one of the standard update-ca-certificates/update-ca-trust locations")
	}

	base := safeFileBase(cert, opts.Name)
	dest := filepath.Join(target.dir, base+target.ext)
	if err := os.WriteFile(dest, certs.EncodePEM(cert), 0o644); err != nil {
		if os.IsPermission(err) {
			return Result{}, fmt.Errorf("writing %s: permission denied (re-run with sudo)", dest)
		}
		return Result{}, fmt.Errorf("writing %s: %w", dest, err)
	}

	out, err := exec.Command(target.updateCmd).CombinedOutput()
	if err != nil {
		_ = os.Remove(dest)
		msg := string(out)
		if msg == "" {
			msg = err.Error()
		}
		return Result{}, fmt.Errorf("%s failed: %s", target.updateCmd, msg)
	}

	return Result{
		Store:       "Linux system trust store (" + dest + ")",
		Command:     target.updateCmd,
		Elevated:    true,
		FirefoxNote: true,
	}, nil
}

func pickTarget() (anchorTarget, bool) {
	for _, t := range linuxTargets {
		if fi, err := os.Stat(t.dir); err == nil && fi.IsDir() {
			return t, true
		}
	}
	return anchorTarget{}, false
}
