package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeCert builds a minimal self-signed CA certificate for testing.
func makeCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func TestParseKeytoolRFC(t *testing.T) {
	a := makeCert(t, "Internal Dev Enterprise CA")
	b := makeCert(t, "Root CA X")

	out := "Keystore type: PKCS12\nKeystore provider: SUN\n\n" +
		"Your keystore contains 2 entries\n\n" +
		"Alias name: internal-dev-ca\n" +
		"Creation date: Jan 1, 2024\n" +
		"Entry type: trustedCertEntry\n\n" +
		pemOf(a) + "\n\n" +
		"Alias name: root-x\n" +
		"Entry type: trustedCertEntry\n\n" +
		pemOf(b) + "\n"

	entries := parseKeytoolRFC([]byte(out))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Alias != "internal-dev-ca" {
		t.Errorf("entry 0 alias = %q, want internal-dev-ca", entries[0].Alias)
	}
	if entries[0].Cert.Subject.CommonName != "Internal Dev Enterprise CA" {
		t.Errorf("entry 0 CN = %q", entries[0].Cert.Subject.CommonName)
	}
	if entries[1].Alias != "root-x" {
		t.Errorf("entry 1 alias = %q, want root-x", entries[1].Alias)
	}
}

func TestParseKeytoolRFC_NoAliasSynthesizes(t *testing.T) {
	a := makeCert(t, "Orphan CA")
	out := pemOf(a) // no "Alias name:" line at all
	entries := parseKeytoolRFC([]byte(out))
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Alias != "Orphan CA" {
		t.Errorf("synthesized alias = %q, want Orphan CA", entries[0].Alias)
	}
}
