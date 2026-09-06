package certs

import (
	"crypto/x509"
	"encoding/pem"
)

// EncodePEM returns the PEM ("CERTIFICATE") encoding of a certificate.
func EncodePEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
