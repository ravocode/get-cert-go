package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFormat_JKS(t *testing.T) {
	dir := t.TempDir()
	path := createEmptyJKS(t, dir, "changeit")

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}
	if format != FormatJKS {
		t.Errorf("format = %v, want JKS", format)
	}
}

func TestDetectFormat_PKCS12(t *testing.T) {
	dir := t.TempDir()
	path := createEmptyPKCS12(t, dir, "changeit")

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}
	if format != FormatPKCS12 {
		t.Errorf("format = %v, want PKCS12", format)
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.bin")
	// Start with a byte that isn't 0xFE (JKS) or 0x30 (PKCS12).
	if err := os.WriteFile(path, []byte{0x00, 0x01, 0x02, 0x03}, 0644); err != nil {
		t.Fatal(err)
	}

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}
	if format != FormatUnknown {
		t.Errorf("format = %v, want Unknown", format)
	}
}

func TestDetectFormat_MissingFile(t *testing.T) {
	_, err := DetectFormat("/nonexistent/path/keystore")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestDetectFormat_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}
	if format != FormatUnknown {
		t.Errorf("format = %v, want Unknown for empty file", format)
	}
}

func TestDetectFormat_JKSMagicBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.jks")
	// Write exactly the JKS magic bytes with no valid payload.
	if err := os.WriteFile(path, []byte{0xFE, 0xED, 0xFE, 0xED}, 0644); err != nil {
		t.Fatal(err)
	}

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatal(err)
	}
	if format != FormatJKS {
		t.Errorf("format = %v, want JKS", format)
	}
}

// ---------- Read() dispatcher ----------

func TestRead_JKS(t *testing.T) {
	dir := t.TempDir()
	password := "changeit"
	path := createEmptyJKS(t, dir, password)

	cert := makeCert(t, "Read JKS CA")
	if err := addJKS(path, password, "read-jks", cert); err != nil {
		t.Fatal(err)
	}

	entries, format, err := Read(path, password)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if format != FormatJKS {
		t.Errorf("format = %v, want JKS", format)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Alias != "read-jks" {
		t.Errorf("alias = %q, want read-jks", entries[0].Alias)
	}
}

func TestRead_PKCS12(t *testing.T) {
	dir := t.TempDir()
	password := "changeit"
	path := createEmptyPKCS12(t, dir, password)

	cert := makeCert(t, "Read P12 CA")
	if err := addPKCS12(path, password, "read-p12", cert); err != nil {
		t.Fatal(err)
	}

	entries, format, err := Read(path, password)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if format != FormatPKCS12 {
		t.Errorf("format = %v, want PKCS12", format)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Cert.Subject.CommonName != "Read P12 CA" {
		t.Errorf("CN = %q, want Read P12 CA", entries[0].Cert.Subject.CommonName)
	}
}

// ---------- Format.String() ----------

func TestFormat_String(t *testing.T) {
	tests := []struct {
		f    Format
		want string
	}{
		{FormatJKS, "JKS"},
		{FormatPKCS12, "PKCS12"},
		{FormatUnknown, "unknown"},
		{Format(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.f.String(); got != tt.want {
			t.Errorf("Format(%d).String() = %q, want %q", int(tt.f), got, tt.want)
		}
	}
}
