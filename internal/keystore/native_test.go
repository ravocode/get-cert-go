package keystore

import (

	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ksjks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// createEmptyJKS creates a minimal, valid JKS keystore file at the given path
// with the given password and returns the path.
func createEmptyJKS(t *testing.T, dir, password string) string {
	t.Helper()
	path := filepath.Join(dir, "test.jks")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	ks := jksNew()
	if err := ks.Store(f, []byte(password)); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	return path
}

// createEmptyPKCS12 creates a minimal, valid PKCS12 trust store file at the
// given path with the given password and returns the path.
func createEmptyPKCS12(t *testing.T, dir, password string) string {
	t.Helper()
	path := filepath.Join(dir, "test.p12")

	// Encode an empty trust store.
	data, err := p12EncodeTrustStoreEntries(nil, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------- JKS round-trip tests ----------

func TestAddJKS_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	password := "testpass"
	path := createEmptyJKS(t, dir, password)

	cert := makeCert(t, "My Test CA")
	if err := addJKS(path, password, "my-test-ca", cert); err != nil {
		t.Fatalf("addJKS failed: %v", err)
	}

	// Read back and verify.
	entries, err := readJKS(path, password)
	if err != nil {
		t.Fatalf("readJKS failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Alias != "my-test-ca" {
		t.Errorf("alias = %q, want my-test-ca", entries[0].Alias)
	}
	if entries[0].Cert.Subject.CommonName != "My Test CA" {
		t.Errorf("CN = %q, want My Test CA", entries[0].Cert.Subject.CommonName)
	}
}

func TestAddJKS_MultipleCerts(t *testing.T) {
	dir := t.TempDir()
	password := "changeit"
	path := createEmptyJKS(t, dir, password)

	certA := makeCert(t, "CA Alpha")
	certB := makeCert(t, "CA Beta")

	if err := addJKS(path, password, "alpha", certA); err != nil {
		t.Fatalf("addJKS(alpha) failed: %v", err)
	}
	if err := addJKS(path, password, "beta", certB); err != nil {
		t.Fatalf("addJKS(beta) failed: %v", err)
	}

	entries, err := readJKS(path, password)
	if err != nil {
		t.Fatalf("readJKS failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	aliases := map[string]bool{}
	for _, e := range entries {
		aliases[e.Alias] = true
	}
	if !aliases["alpha"] || !aliases["beta"] {
		t.Errorf("aliases = %v, want {alpha, beta}", aliases)
	}
}

func TestAddJKS_PreservesExistingEntries(t *testing.T) {
	dir := t.TempDir()
	password := "changeit"
	path := createEmptyJKS(t, dir, password)

	existing := makeCert(t, "Existing CA")
	if err := addJKS(path, password, "existing-ca", existing); err != nil {
		t.Fatal(err)
	}

	newCert := makeCert(t, "New CA")
	if err := addJKS(path, password, "new-ca", newCert); err != nil {
		t.Fatal(err)
	}

	entries, err := readJKS(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	found := map[string]string{}
	for _, e := range entries {
		found[e.Alias] = e.Cert.Subject.CommonName
	}
	if found["existing-ca"] != "Existing CA" {
		t.Errorf("existing entry lost or renamed: %v", found)
	}
	if found["new-ca"] != "New CA" {
		t.Errorf("new entry not found: %v", found)
	}
}

// ---------- PKCS12 round-trip tests ----------

func TestAddPKCS12_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	password := "testpass"
	path := createEmptyPKCS12(t, dir, password)

	cert := makeCert(t, "PKCS12 Test CA")
	if err := addPKCS12(path, password, "pkcs12-test", cert); err != nil {
		t.Fatalf("addPKCS12 failed: %v", err)
	}

	entries, err := readPKCS12(path, password)
	if err != nil {
		t.Fatalf("readPKCS12 failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Cert.Subject.CommonName != "PKCS12 Test CA" {
		t.Errorf("CN = %q, want PKCS12 Test CA", entries[0].Cert.Subject.CommonName)
	}
}

func TestAddPKCS12_DeduplicatesSameCert(t *testing.T) {
	dir := t.TempDir()
	password := "changeit"
	path := createEmptyPKCS12(t, dir, password)

	cert := makeCert(t, "Dup CA")

	if err := addPKCS12(path, password, "dup-ca", cert); err != nil {
		t.Fatal(err)
	}
	// Import the same cert again.
	if err := addPKCS12(path, password, "dup-ca-2", cert); err != nil {
		t.Fatal(err)
	}

	entries, err := readPKCS12(path, password)
	if err != nil {
		t.Fatal(err)
	}
	// The second import should replace, not duplicate.
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after dedup, got %d", len(entries))
	}
}

// ---------- writeFileAtomic tests ----------

func TestWriteFileAtomic_PreservesPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission semantics differ on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "target")

	// Create a file with 0755 permissions (unusual for a keystore, easy to detect).
	if err := os.WriteFile(path, []byte("original"), 0755); err != nil {
		t.Fatal(err)
	}

	err := writeFileAtomic(path, func(w *os.File) error {
		_, err := w.Write([]byte("replaced"))
		return err
	})
	if err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
	}

	// Verify content.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "replaced" {
		t.Errorf("content = %q, want replaced", data)
	}

	// Verify permissions preserved.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0755 {
		t.Errorf("permissions = %o, want 755", fi.Mode().Perm())
	}
}

func TestWriteFileAtomic_FailedWriteDoesNotCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	original := []byte("do not corrupt me")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}

	// Simulate a write failure.
	err := writeFileAtomic(path, func(_ *os.File) error {
		return os.ErrPermission
	})
	if err == nil {
		t.Fatal("expected error from writeFileAtomic")
	}

	// Original file must be unchanged.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Errorf("original file was corrupted: got %q", data)
	}
}

// ---------- Import (force native) integration test ----------

func TestImport_ForceNative_JKS(t *testing.T) {
	dir := t.TempDir()
	password := "changeit"
	path := createEmptyJKS(t, dir, password)

	cert := makeCert(t, "Force Native JKS CA")
	res, err := Import(path, password, "native-jks", cert, true)
	if err != nil {
		t.Fatalf("Import with forceNative failed: %v", err)
	}
	if res.Method != "native" {
		t.Errorf("method = %q, want native", res.Method)
	}
	if res.Format != FormatJKS {
		t.Errorf("format = %v, want JKS", res.Format)
	}
	if res.Warning != "" {
		t.Errorf("unexpected warning for JKS: %q", res.Warning)
	}

	// Verify via Read().
	entries, fmt, err := Read(path, password)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if fmt != FormatJKS {
		t.Errorf("Read format = %v, want JKS", fmt)
	}
	if len(entries) != 1 || entries[0].Cert.Subject.CommonName != "Force Native JKS CA" {
		t.Errorf("unexpected entries: %v", entries)
	}
}

func TestImport_ForceNative_PKCS12(t *testing.T) {
	dir := t.TempDir()
	password := "changeit"
	path := createEmptyPKCS12(t, dir, password)

	cert := makeCert(t, "Force Native P12 CA")
	res, err := Import(path, password, "native-p12", cert, true)
	if err != nil {
		t.Fatalf("Import with forceNative failed: %v", err)
	}
	if res.Method != "native" {
		t.Errorf("method = %q, want native", res.Method)
	}
	if res.Format != FormatPKCS12 {
		t.Errorf("format = %v, want PKCS12", res.Format)
	}
	if res.Warning == "" {
		t.Error("expected PKCS12 alias-regeneration warning, got none")
	}
}

// ---------- helpers ----------

// jksNew and p12EncodeTrustStoreEntries are thin wrappers to avoid importing
// the libraries a second time (they are already imported in the production
// code under package-level aliases).

func jksNew() interface{ Store(io.Writer, []byte) error } {
	return ksjks.New()
}

func p12EncodeTrustStoreEntries(entries []p12TrustEntry, password string) ([]byte, error) {
	var converted []pkcs12.TrustStoreEntry
	for _, e := range entries {
		converted = append(converted, pkcs12.TrustStoreEntry{
			Cert:         e.Cert,
			FriendlyName: e.Name,
		})
	}
	return pkcs12.LegacyRC2.EncodeTrustStoreEntries(converted, password)
}

type p12TrustEntry struct {
	Cert *x509.Certificate
	Name string
}
