// Package ui provides terminal presentation helpers: colored status output,
// aligned tables, and interactive prompts.
package ui

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	survey "github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"

	"github.com/ravocode/get-cert-go/internal/certs"
)

var (
	bold    = color.New(color.Bold)
	dim     = color.New(color.Faint)
	green   = color.New(color.FgGreen)
	red     = color.New(color.FgRed)
	yellow  = color.New(color.FgYellow)
	cyan    = color.New(color.FgCyan)
	magenta = color.New(color.FgMagenta)
)

// Infof prints an informational line.
func Infof(format string, a ...any) { fmt.Println(cyan.Sprintf(format, a...)) }

// Successf prints a success line prefixed with a check mark.
func Successf(format string, a ...any) {
	fmt.Printf("%s %s\n", green.Sprint("\u2705"), fmt.Sprintf(format, a...))
}

// Warnf prints a warning line.
func Warnf(format string, a ...any) {
	fmt.Printf("%s %s\n", yellow.Sprint("\u26a0"), fmt.Sprintf(format, a...))
}

// Errorf prints an error line to stderr.
func Errorf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", red.Sprint("\u2717"), fmt.Sprintf(format, a...))
}

// Headingf prints a bold heading.
func Headingf(format string, a ...any) { fmt.Println(bold.Sprintf(format, a...)) }

// RenderChain prints a color-coded table describing a certificate chain.
func RenderChain(chain []*x509.Certificate, now time.Time) {
	headers := []string{"#", "ROLE", "COMMON NAME", "ISSUER", "VALID FROM", "VALID TO", "STATUS"}
	rows := make([][]cell, 0, len(chain))

	for i, c := range chain {
		role := string(certs.ClassifyRole(c, i))
		status, desc := certs.Expiry(c, now)

		roleCell := plain(role)
		switch certs.Role(role) {
		case certs.RoleRoot:
			roleCell = colored(role, magenta)
		case certs.RoleIntermediate:
			roleCell = colored(role, cyan)
		}

		rows = append(rows, []cell{
			plain(fmt.Sprintf("%d", i)),
			roleCell,
			plain(truncate(certs.CommonName(c), 40)),
			plain(truncate(certs.IssuerName(c), 40)),
			plain(c.NotBefore.Format("2006-01-02")),
			plain(c.NotAfter.Format("2006-01-02")),
			statusCell(status, desc),
		})
	}

	printTable(headers, rows)

	fmt.Println()
	for i, c := range chain {
		dim.Printf("  [%d] SHA-256: %s\n", i, certs.Fingerprint(c))
	}
}

func statusCell(status certs.ExpiryStatus, desc string) cell {
	switch status {
	case certs.StatusExpired:
		return colored(desc, red)
	case certs.StatusExpiringSoon:
		return colored(desc, yellow)
	default:
		return colored(desc, green)
	}
}

// ExpiryLabel returns a short colored expiry label for inline use.
func ExpiryLabel(c *x509.Certificate, now time.Time) string {
	status, desc := certs.Expiry(c, now)
	switch status {
	case certs.StatusExpired:
		return red.Sprint(desc)
	case certs.StatusExpiringSoon:
		return yellow.Sprint(desc)
	default:
		return green.Sprint(desc)
	}
}

// SelectCertificates presents an interactive multi-select of the chain and
// returns the indexes the user chose to trust. CA certificates are preselected
// by default since those are what usually need to be added to a trust store.
func SelectCertificates(chain []*x509.Certificate, now time.Time) ([]int, error) {
	options := make([]string, len(chain))
	defaults := make([]string, 0, len(chain))
	for i, c := range chain {
		role := certs.ClassifyRole(c, i)
		_, desc := certs.Expiry(c, now)
		label := fmt.Sprintf("[%d] %s: %s (%s)", i, role, certs.CommonName(c), desc)
		options[i] = label
		if role != certs.RoleLeaf {
			defaults = append(defaults, label)
		}
	}

	var chosen []string
	prompt := &survey.MultiSelect{
		Message: "Select certificates to import:",
		Options: options,
		Default: defaults,
	}
	if err := survey.AskOne(prompt, &chosen); err != nil {
		return nil, err
	}

	index := make(map[string]int, len(options))
	for i, o := range options {
		index[o] = i
	}
	out := make([]int, 0, len(chosen))
	for _, ch := range chosen {
		if i, ok := index[ch]; ok {
			out = append(out, i)
		}
	}
	return out, nil
}

// AskPassword prompts for a keystore password without echoing input. If the
// user submits an empty value, def is returned.
func AskPassword(promptText, def string) (string, error) {
	var pw string
	prompt := &survey.Password{Message: promptText}
	if err := survey.AskOne(prompt, &pw); err != nil {
		return "", err
	}
	if pw == "" {
		return def, nil
	}
	return pw, nil
}

// AskString prompts for a free-form string with a default value.
func AskString(promptText, def string) (string, error) {
	var s string
	prompt := &survey.Input{Message: promptText, Default: def}
	if err := survey.AskOne(prompt, &s); err != nil {
		return "", err
	}
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return s, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "\u2026"
}
