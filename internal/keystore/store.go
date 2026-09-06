package keystore

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	ksjks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Format identifies the on-disk encoding of a keystore.
type Format int

const (
	FormatUnknown Format = iota
	FormatJKS
	FormatPKCS12
)

func (f Format) String() string {
	switch f {
	case FormatJKS:
		return "JKS"
	case FormatPKCS12:
		return "PKCS12"
	default:
		return "unknown"
	}
}

// Entry is a single trusted certificate entry in a keystore.
type Entry struct {
	Alias string
	Cert  *x509.Certificate
}

// jksMagic is the four-byte magic number at the start of a JKS file.
var jksMagic = []byte{0xFE, 0xED, 0xFE, 0xED}

// DetectFormat inspects the leading bytes of a keystore file to guess whether
// it is a JKS or PKCS12 store.
func DetectFormat(path string) (Format, error) {
	f, err := os.Open(path)
	if err != nil {
		return FormatUnknown, err
	}
	defer f.Close()

	head := make([]byte, 4)
	n, _ := f.Read(head)
	if n >= 4 && bytes.Equal(head[:4], jksMagic) {
		return FormatJKS, nil
	}
	// PKCS12 is DER-encoded ASN.1; the outer SEQUENCE begins with 0x30.
	if n >= 1 && head[0] == 0x30 {
		return FormatPKCS12, nil
	}
	return FormatUnknown, nil
}

// Read loads all trusted certificate entries from the keystore at path. JKS
// stores preserve their original aliases; PKCS12 trust stores that do not carry
// friendly names have aliases synthesized from the certificate subject.
func Read(path, password string) ([]Entry, Format, error) {
	format, err := DetectFormat(path)
	if err != nil {
		return nil, FormatUnknown, err
	}

	switch format {
	case FormatJKS:
		entries, err := readJKS(path, password)
		if err == nil {
			return entries, FormatJKS, nil
		}
		if e2, kerr := readViaKeytool(path, password); kerr == nil {
			return e2, FormatJKS, nil
		}
		return nil, FormatJKS, err
	case FormatPKCS12:
		entries, err := readPKCS12(path, password)
		if err == nil {
			return entries, FormatPKCS12, nil
		}
		// The strict PKCS12 decoder rejects some JDK cacerts (e.g. MAC-less
		// stores: "no MAC in data"); fall back to keytool, which reads any
		// JDK-supported store.
		e2, kerr := readViaKeytool(path, password)
		if kerr == nil {
			return e2, FormatPKCS12, nil
		}
		return nil, FormatPKCS12, combineReadErr(err, kerr)
	default:
		// Fall back: try PKCS12, then JKS, then keytool.
		if entries, err := readPKCS12(path, password); err == nil {
			return entries, FormatPKCS12, nil
		}
		if entries, err := readJKS(path, password); err == nil {
			return entries, FormatJKS, nil
		}
		if entries, err := readViaKeytool(path, password); err == nil {
			return entries, FormatUnknown, nil
		}
		return nil, FormatUnknown, fmt.Errorf("unrecognized keystore format for %s", path)
	}
}

// readViaKeytool reads a keystore using the JDK keytool as a fallback for
// stores the native parsers cannot handle.
func readViaKeytool(path, password string) ([]Entry, error) {
	keytool, ok := FindKeytool(path)
	if !ok {
		return nil, errKeytoolNotFound
	}
	return ReadWithKeytool(keytool, path, password)
}

// errKeytoolNotFound signals that the keytool fallback could not run.
var errKeytoolNotFound = fmt.Errorf("keytool not found")

// combineReadErr produces a helpful error when native parsing fails and the
// keytool fallback could not be used.
func combineReadErr(native, fallback error) error {
	if fallback == errKeytoolNotFound {
		return fmt.Errorf("%w; a JDK 'keytool' was not found to read this store "+
			"(set JAVA_HOME or add keytool to PATH)", native)
	}
	return fmt.Errorf("%w (keytool fallback also failed: %v)", native, fallback)
}

func readJKS(path, password string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ks := ksjks.New()
	if err := ks.Load(f, []byte(password)); err != nil {
		return nil, fmt.Errorf("reading JKS keystore: %w", err)
	}

	var entries []Entry
	for _, alias := range ks.Aliases() {
		if !ks.IsTrustedCertificateEntry(alias) {
			continue
		}
		tce, err := ks.GetTrustedCertificateEntry(alias)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(tce.Certificate.Content)
		if err != nil {
			continue
		}
		entries = append(entries, Entry{Alias: alias, Cert: cert})
	}
	return entries, nil
}

func readPKCS12(path, password string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs, err := pkcs12.DecodeTrustStore(data, password)
	if err != nil {
		return nil, fmt.Errorf("reading PKCS12 trust store: %w", err)
	}
	entries := make([]Entry, 0, len(certs))
	seen := map[string]int{}
	for _, c := range certs {
		alias := suggestPKCSAlias(c, seen)
		entries = append(entries, Entry{Alias: alias, Cert: c})
	}
	return entries, nil
}

// suggestPKCSAlias derives a display alias for a PKCS12 entry that lacks a
// stored friendly name, disambiguating collisions with a numeric suffix.
func suggestPKCSAlias(c *x509.Certificate, seen map[string]int) string {
	base := aliasFromCert(c)
	seen[base]++
	if n := seen[base]; n > 1 {
		return fmt.Sprintf("%s-%d", base, n)
	}
	return base
}

func aliasFromCert(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.Subject.Organization) > 0 {
		return c.Subject.Organization[0]
	}
	return c.Subject.String()
}

// entryTime is used when creating new JKS entries.
func entryTime() time.Time { return time.Now() }
