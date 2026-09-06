package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// makeCert builds a self-signed CA certificate for testing.
func makeCert(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: cn}, // self-signed
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
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

// makeLeafCert builds a leaf (non-CA) certificate with a different issuer.
func makeLeafCert(t *testing.T, cn, issuerCN string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
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

// ---------- ParseTarget ----------

func TestParseTarget_URL(t *testing.T) {
	target, err := ParseTarget("https://example.com/path")
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "example.com" {
		t.Errorf("host = %q, want example.com", target.Host)
	}
	if target.Port != "443" {
		t.Errorf("port = %q, want 443", target.Port)
	}
}

func TestParseTarget_URLWithPort(t *testing.T) {
	target, err := ParseTarget("https://example.com:8443/api")
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "example.com" {
		t.Errorf("host = %q, want example.com", target.Host)
	}
	if target.Port != "8443" {
		t.Errorf("port = %q, want 8443", target.Port)
	}
}

func TestParseTarget_BareHost(t *testing.T) {
	target, err := ParseTarget("myhost.local")
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "myhost.local" {
		t.Errorf("host = %q, want myhost.local", target.Host)
	}
	if target.Port != "443" {
		t.Errorf("port = %q, want 443", target.Port)
	}
}

func TestParseTarget_HostPort(t *testing.T) {
	target, err := ParseTarget("myhost.local:9443")
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "myhost.local" {
		t.Errorf("host = %q, want myhost.local", target.Host)
	}
	if target.Port != "9443" {
		t.Errorf("port = %q, want 9443", target.Port)
	}
}

func TestParseTarget_Empty(t *testing.T) {
	_, err := ParseTarget("")
	if err == nil {
		t.Error("expected error for empty target")
	}
}

func TestParseTarget_Whitespace(t *testing.T) {
	_, err := ParseTarget("   ")
	if err == nil {
		t.Error("expected error for whitespace-only target")
	}
}

func TestTarget_Address(t *testing.T) {
	tgt := Target{Host: "example.com", Port: "443"}
	if got := tgt.Address(); got != "example.com:443" {
		t.Errorf("Address() = %q, want example.com:443", got)
	}
}

// ---------- ClassifyRole ----------

func TestClassifyRole_SelfSignedCA(t *testing.T) {
	cert := makeCert(t, "Root CA", true)
	role := ClassifyRole(cert, 0)
	if role != RoleRoot {
		t.Errorf("role = %q, want Root", role)
	}
}

func TestClassifyRole_Leaf(t *testing.T) {
	cert := makeLeafCert(t, "leaf.example.com", "Some CA")
	role := ClassifyRole(cert, 0)
	if role != RoleLeaf {
		t.Errorf("role = %q, want Leaf", role)
	}
}

func TestClassifyRole_Intermediate(t *testing.T) {
	// Generate parent (Root)
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDer, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDer)

	// Generate intermediate signed by Root
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true, // Must be CA
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, rootCert, &key.PublicKey, rootKey)
	cert, _ := x509.ParseCertificate(der)

	role := ClassifyRole(cert, 1)
	if role != RoleIntermediate {
		t.Errorf("role = %q, want Intermediate", role)
	}
}

// ---------- Expiry ----------

func TestExpiry_Valid(t *testing.T) {
	cert := makeCert(t, "Valid CA", true)
	status, desc := Expiry(cert, time.Now())
	if status != StatusValid {
		t.Errorf("status = %d, want StatusValid", status)
	}
	if desc == "" {
		t.Error("expected non-empty description")
	}
}

func TestExpiry_Expired(t *testing.T) {
	cert := makeCert(t, "Expired CA", true)
	// Check expiry a year after the cert expires.
	future := cert.NotAfter.Add(365 * 24 * time.Hour)
	status, desc := Expiry(cert, future)
	if status != StatusExpired {
		t.Errorf("status = %d, want StatusExpired", status)
	}
	if desc == "" {
		t.Error("expected non-empty description")
	}
}

func TestExpiry_ExpiringSoon(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Soon CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 24 * time.Hour), // 10 days < 30-day window
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	status, _ := Expiry(cert, time.Now())
	if status != StatusExpiringSoon {
		t.Errorf("status = %d, want StatusExpiringSoon", status)
	}
}

func TestExpiry_NotYetValid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Future CA"},
		NotBefore:             time.Now().Add(24 * time.Hour), // starts tomorrow
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	status, desc := Expiry(cert, time.Now())
	if status != StatusExpiringSoon {
		t.Errorf("status = %d, want StatusExpiringSoon (not yet valid)", status)
	}
	if desc == "" {
		t.Error("expected non-empty description")
	}
}

// ---------- CommonName / IssuerName ----------

func TestCommonName(t *testing.T) {
	cert := makeCert(t, "My CA", true)
	if got := CommonName(cert); got != "My CA" {
		t.Errorf("CommonName = %q, want My CA", got)
	}
}

func TestCommonName_FallbackToOrg(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Acme Corp"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	if got := CommonName(cert); got != "Acme Corp" {
		t.Errorf("CommonName = %q, want Acme Corp", got)
	}
}

func TestIssuerName(t *testing.T) {
	cert := makeCert(t, "Issuer Test", true)
	// Self-signed, so issuer CN == subject CN.
	if got := IssuerName(cert); got != "Issuer Test" {
		t.Errorf("IssuerName = %q, want Issuer Test", got)
	}
}

// ---------- SuggestAlias ----------

func TestSuggestAlias(t *testing.T) {
	tests := []struct {
		cn   string
		want string
	}{
		{"Internal Dev Enterprise CA", "internal-dev-enterprise-ca"},
		{"Root CA X", "root-ca-x"},
		{"DigiCert Global Root G2", "digicert-global-root-g2"},
	}
	for _, tt := range tests {
		cert := makeCert(t, tt.cn, true)
		if got := SuggestAlias(cert); got != tt.want {
			t.Errorf("SuggestAlias(%q) = %q, want %q", tt.cn, got, tt.want)
		}
	}
}

func TestSuggestAlias_EmptyCN(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	got := SuggestAlias(cert)
	if got != "cert" {
		t.Errorf("SuggestAlias(empty CN) = %q, want cert", got)
	}
}

// ---------- Fingerprint ----------

func TestFingerprint_Format(t *testing.T) {
	cert := makeCert(t, "FP Test", true)
	fp := Fingerprint(cert)
	// SHA-256 = 32 bytes = 64 hex chars + 31 colons = 95 characters.
	if len(fp) != 95 {
		t.Errorf("Fingerprint length = %d, want 95", len(fp))
	}
	// Check colon-separated format.
	parts := 0
	for _, ch := range fp {
		if ch == ':' {
			parts++
		}
	}
	if parts != 31 {
		t.Errorf("colon count = %d, want 31", parts)
	}
}

func TestFingerprintCompact(t *testing.T) {
	cert := makeCert(t, "FP Compact Test", true)
	fp := FingerprintCompact(cert)
	// SHA-256 = 64 hex chars, no separators.
	if len(fp) != 64 {
		t.Errorf("FingerprintCompact length = %d, want 64", len(fp))
	}
}

// ---------- EncodePEM ----------

func TestEncodePEM(t *testing.T) {
	cert := makeCert(t, "PEM Test", true)
	pem := EncodePEM(cert)
	if len(pem) == 0 {
		t.Fatal("EncodePEM returned empty")
	}
	pemStr := string(pem)
	if !contains(pemStr, "-----BEGIN CERTIFICATE-----") {
		t.Error("missing PEM header")
	}
	if !contains(pemStr, "-----END CERTIFICATE-----") {
		t.Error("missing PEM footer")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
