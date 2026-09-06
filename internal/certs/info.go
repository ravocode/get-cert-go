package certs

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Role classifies a certificate's position within a chain.
type Role string

const (
	RoleLeaf         Role = "Leaf"
	RoleIntermediate Role = "Intermediate"
	RoleRoot         Role = "Root"
)

// ClassifyRole determines a certificate's role given its index in the chain.
// Index 0 is the leaf (unless it is a self-signed CA).
func ClassifyRole(c *x509.Certificate, index int) Role {
	selfSigned := c.Subject.String() == c.Issuer.String()
	if selfSigned && c.IsCA {
		return RoleRoot
	}
	if index == 0 {
		return RoleLeaf
	}
	if c.IsCA {
		return RoleIntermediate
	}
	return RoleLeaf
}

// ExpiryStatus describes how close a certificate is to expiry.
type ExpiryStatus int

const (
	StatusValid ExpiryStatus = iota
	StatusExpiringSoon
	StatusExpired
)

// ExpiringWindow is how far in advance a cert is flagged as "expiring soon".
const ExpiringWindow = 30 * 24 * time.Hour

// Expiry returns the status and a human-readable description relative to now.
func Expiry(c *x509.Certificate, now time.Time) (ExpiryStatus, string) {
	if now.Before(c.NotBefore) {
		return StatusExpiringSoon, fmt.Sprintf("Not valid until %s", c.NotBefore.Format("2006-01-02"))
	}
	if now.After(c.NotAfter) {
		return StatusExpired, fmt.Sprintf("Expired %s ago", humanDuration(now.Sub(c.NotAfter)))
	}
	remaining := c.NotAfter.Sub(now)
	status := StatusValid
	if remaining < ExpiringWindow {
		status = StatusExpiringSoon
	}
	return status, fmt.Sprintf("Expires in %s", humanDuration(remaining))
}

func humanDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 365:
		years := days / 365
		rem := days % 365
		if rem == 0 {
			return plural(years, "year")
		}
		return fmt.Sprintf("%s %s", plural(years, "year"), plural(rem, "day"))
	case days > 0:
		return plural(days, "day")
	default:
		return plural(int(d.Hours()), "hour")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// Fingerprint returns the uppercase, colon-separated SHA-256 fingerprint.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return colonHex(sum[:])
}

// FingerprintCompact returns the SHA-256 fingerprint without separators.
func FingerprintCompact(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func colonHex(b []byte) string {
	s := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i+2 <= len(s); i += 2 {
		parts = append(parts, s[i:i+2])
	}
	return strings.Join(parts, ":")
}

// CommonName returns the subject CN, falling back to the first organization or
// the full distinguished name.
func CommonName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.Subject.Organization) > 0 {
		return c.Subject.Organization[0]
	}
	return c.Subject.String()
}

// IssuerName returns the issuer CN, falling back to the first organization or
// the full distinguished name.
func IssuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.String()
}

var aliasCleaner = regexp.MustCompile(`[^a-z0-9]+`)

// SuggestAlias derives a stable, keystore-friendly alias from a certificate's
// common name, e.g. "Internal Dev Enterprise CA" -> "internal-dev-enterprise-ca".
func SuggestAlias(c *x509.Certificate) string {
	base := CommonName(c)
	base = strings.ToLower(base)
	base = aliasCleaner.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "cert"
	}
	return base
}
