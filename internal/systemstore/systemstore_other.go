//go:build !windows && !darwin && !linux

package systemstore

import (
	"crypto/x509"
	"fmt"
	"runtime"
)

// install is a stub for operating systems without a supported trust store
// integration.
func install(_ *x509.Certificate, _ Options) (Result, error) {
	return Result{}, fmt.Errorf("system trust store import is not supported on %s", runtime.GOOS)
}
