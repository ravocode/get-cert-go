package cli

import (
	"fmt"

	"github.com/ravocode/get-cert-go/internal/keystore"
	"github.com/ravocode/get-cert-go/internal/ui"
)

// resolveKeystore returns the keystore path to use: the explicit --keystore
// flag, or an auto-discovered JVM cacerts file.
func resolveKeystore() (string, error) {
	if flagKeystore != "" {
		return flagKeystore, nil
	}
	path, err := keystore.DiscoverCACerts()
	if err != nil {
		return "", err
	}
	return path, nil
}

// resolvePassword returns the keystore password: the --password flag if set,
// otherwise an interactive prompt that defaults to the well-known "changeit".
// When prompting is not desired (interactive is false) it returns the default.
func resolvePassword(keystorePath string, interactive bool) (string, error) {
	if flagPassword != "" {
		return flagPassword, nil
	}
	if !interactive {
		return keystore.DefaultPassword, nil
	}
	prompt := fmt.Sprintf("Password for keystore (%s):", keystorePath)
	return ui.AskPassword(prompt, keystore.DefaultPassword)
}
