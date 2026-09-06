// Package keystore locates and manipulates Java keystores (JKS and PKCS12)
// used as certificate trust stores.
package keystore

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// DefaultPassword is the well-known default password for a JVM cacerts file.
const DefaultPassword = "changeit"

// DiscoverCACerts attempts to locate the JVM's default cacerts trust store. It
// checks JAVA_HOME first, then common OS-specific JDK install locations,
// preferring newer versions when several are found.
func DiscoverCACerts() (string, error) {
	for _, c := range candidatePaths() {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("could not locate a JVM cacerts file; pass one explicitly with --keystore")
}

// candidatePaths returns cacerts locations to probe, most-preferred first.
func candidatePaths() []string {
	var out []string

	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		out = append(out,
			filepath.Join(jh, "lib", "security", "cacerts"),
			filepath.Join(jh, "jre", "lib", "security", "cacerts"),
		)
	}

	for _, g := range osGlobs() {
		matches, _ := filepath.Glob(g)
		// Reverse-sort so that higher version directories sort first.
		sort.Sort(sort.Reverse(sort.StringSlice(matches)))
		out = append(out, matches...)
	}
	return out
}

func osGlobs() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\Program Files\Java\*\lib\security\cacerts`,
			`C:\Program Files\Java\*\jre\lib\security\cacerts`,
			`C:\Program Files\Eclipse Adoptium\*\lib\security\cacerts`,
			`C:\Program Files\Microsoft\jdk-*\lib\security\cacerts`,
			`C:\Program Files\Amazon Corretto\*\lib\security\cacerts`,
			`C:\Program Files (x86)\Java\*\lib\security\cacerts`,
		}
	case "darwin":
		return []string{
			"/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts",
			"/Library/Java/JavaVirtualMachines/*/Contents/Home/jre/lib/security/cacerts",
			"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts",
		}
	default: // linux and other unix
		return []string{
			"/usr/lib/jvm/*/lib/security/cacerts",
			"/usr/lib/jvm/*/jre/lib/security/cacerts",
			"/etc/ssl/certs/java/cacerts",
			"/opt/java/*/lib/security/cacerts",
		}
	}
}
