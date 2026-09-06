package keystore

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// FindKeytool locates the JDK "keytool" executable. It prefers a keytool that
// lives alongside the given keystore (…/bin/keytool relative to …/lib/security/
// cacerts), then JAVA_HOME/bin, then the system PATH.
func FindKeytool(keystorePath string) (string, bool) {
	exe := "keytool"
	if runtime.GOOS == "windows" {
		exe = "keytool.exe"
	}

	var candidates []string
	if keystorePath != "" {
		// cacerts is typically at <home>/lib/security/cacerts, so keytool is at
		// <home>/bin/keytool. Walk up three directories.
		home := filepath.Dir(filepath.Dir(filepath.Dir(keystorePath)))
		candidates = append(candidates, filepath.Join(home, "bin", exe))
	}
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		candidates = append(candidates, filepath.Join(jh, "bin", exe))
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, true
		}
	}
	if p, err := exec.LookPath(exe); err == nil {
		return p, true
	}
	return "", false
}

// AliasExists reports whether an alias is already present in the keystore using
// keytool. It is best-effort: on any error it returns false.
func AliasExists(keytool, keystorePath, password, alias string) bool {
	cmd := exec.Command(keytool,
		"-list",
		"-keystore", keystorePath,
		"-storepass", password,
		"-alias", alias,
	)
	return cmd.Run() == nil
}

// ImportWithKeytool imports a single PEM-encoded certificate into the keystore
// under the given alias. The certificate is fed via stdin and "-noprompt"
// auto-confirms the trust question. It works for both JKS and PKCS12 stores and
// preserves all existing entries and their aliases.
func ImportWithKeytool(keytool, keystorePath, password, alias string, pemBytes []byte) error {
	cmd := exec.Command(keytool,
		"-importcert",
		"-noprompt",
		"-trustcacerts",
		"-keystore", keystorePath,
		"-storepass", password,
		"-alias", alias,
	)
	cmd.Stdin = bytes.NewReader(pemBytes)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("keytool import failed: %s", msg)
	}
	return nil
}

// ReadWithKeytool lists trusted certificate entries by shelling out to
// "keytool -list -rfc". This is used as a fallback when the native parser
// cannot read a store (e.g. a JDK cacerts written without a MAC, which the
// strict PKCS12 decoder rejects with "no MAC in data"). keytool can read any
// keystore format the installed JDK supports. Output is forced to English so
// the "Alias name:" markers are parseable.
func ReadWithKeytool(keytool, keystorePath, password string) ([]Entry, error) {
	cmd := exec.Command(keytool,
		"-list",
		"-rfc",
		"-J-Duser.language=en",
		"-keystore", keystorePath,
		"-storepass", password,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("keytool list failed: %s", msg)
	}
	return parseKeytoolRFC(stdout.Bytes()), nil
}

// parseKeytoolRFC extracts entries from "keytool -list -rfc" output, pairing
// each PEM certificate block with the most recent "Alias name:" line. When no
// alias precedes a certificate the alias is synthesized from the subject.
func parseKeytoolRFC(data []byte) []Entry {
	var entries []Entry
	var currentAlias string
	var pemBuf strings.Builder
	inPem := false
	seen := map[string]int{}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, "Alias name: ") {
			currentAlias = strings.TrimSpace(strings.TrimPrefix(line, "Alias name: "))
			continue
		}
		if strings.Contains(line, "-----BEGIN CERTIFICATE-----") {
			inPem = true
			pemBuf.Reset()
		}
		if inPem {
			pemBuf.WriteString(line)
			pemBuf.WriteByte('\n')
			if strings.Contains(line, "-----END CERTIFICATE-----") {
				inPem = false
				block, _ := pem.Decode([]byte(pemBuf.String()))
				if block == nil {
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					continue
				}
				alias := currentAlias
				if alias == "" {
					alias = aliasFromCert(cert)
				}
				seen[alias]++
				if seen[alias] > 1 {
					alias = fmt.Sprintf("%s-%d", alias, seen[alias])
				}
				entries = append(entries, Entry{Alias: alias, Cert: cert})
				currentAlias = ""
			}
		}
	}
	return entries
}

