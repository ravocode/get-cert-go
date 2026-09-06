package keystore

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ravocode/get-cert-go/internal/certs"
	ksjks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ImportResult describes the outcome of an import operation.
type ImportResult struct {
	Alias   string
	Method  string // "keytool" or "native"
	Format  Format
	Warning string
}

// Import adds a single trusted certificate to the keystore under the given
// alias. When keytool is available (and forceNative is false) it is used, as it
// safely preserves every existing entry regardless of store format. Otherwise a
// native Go implementation is used: JKS stores round-trip losslessly, while
// native PKCS12 writes regenerate the friendly names of pre-existing entries.
func Import(keystorePath, password, alias string, cert *x509.Certificate, forceNative bool) (ImportResult, error) {
	format, err := DetectFormat(keystorePath)
	if err != nil {
		return ImportResult{}, err
	}
	res := ImportResult{Alias: alias, Format: format}

	if !forceNative {
		if keytool, ok := FindKeytool(keystorePath); ok {
			if err := ImportWithKeytool(keytool, keystorePath, password, alias, certs.EncodePEM(cert)); err != nil {
				return ImportResult{}, err
			}
			res.Method = "keytool"
			return res, nil
		}
	}

	res.Method = "native"
	switch format {
	case FormatJKS:
		return res, addJKS(keystorePath, password, alias, cert)
	case FormatPKCS12:
		res.Warning = "native PKCS12 write: aliases of pre-existing entries may be regenerated"
		return res, addPKCS12(keystorePath, password, alias, cert)
	default:
		return ImportResult{}, fmt.Errorf("cannot natively import into an unrecognized keystore format; install a JDK so keytool can be used")
	}
}

func addJKS(path, password, alias string, cert *x509.Certificate) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	ks := ksjks.New()
	if err := ks.Load(f, []byte(password)); err != nil {
		f.Close()
		return fmt.Errorf("reading JKS keystore: %w", err)
	}
	f.Close()

	if err := ks.SetTrustedCertificateEntry(alias, ksjks.TrustedCertificateEntry{
		CreationTime: entryTime(),
		Certificate: ksjks.Certificate{
			Type:    "X.509",
			Content: cert.Raw,
		},
	}); err != nil {
		return fmt.Errorf("adding entry %q: %w", alias, err)
	}

	return writeFileAtomic(path, func(w *os.File) error {
		return ks.Store(w, []byte(password))
	})
}

func addPKCS12(path, password, alias string, cert *x509.Certificate) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	existing, err := pkcs12.DecodeTrustStore(data, password)
	if err != nil {
		return fmt.Errorf("reading PKCS12 trust store: %w", err)
	}

	entries := make([]pkcs12.TrustStoreEntry, 0, len(existing)+1)
	seen := map[string]int{}
	for _, c := range existing {
		if c.Equal(cert) {
			continue // avoid duplicating the same certificate
		}
		entries = append(entries, pkcs12.TrustStoreEntry{
			Cert:         c,
			FriendlyName: suggestPKCSAlias(c, seen),
		})
	}
	entries = append(entries, pkcs12.TrustStoreEntry{Cert: cert, FriendlyName: alias})

	out, err := pkcs12.EncodeTrustStoreEntries(rand.Reader, entries, password)
	if err != nil {
		return fmt.Errorf("encoding PKCS12 trust store: %w", err)
	}

	return writeFileAtomic(path, func(w *os.File) error {
		_, err := w.Write(out)
		return err
	})
}

// writeFileAtomic writes to a temp file in the same directory and renames it
// over the target, so a failed write cannot corrupt the existing keystore.
// It preserves the original file's permissions so the replacement is
// readable by the same users (e.g. JVM service accounts reading cacerts).
func writeFileAtomic(path string, write func(*os.File) error) error {
	// Capture original permissions before we start.
	mode := os.FileMode(0644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode()
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cert-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	// Apply original permissions to the temp file before writing.
	_ = tmp.Chmod(mode)

	if err := write(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
