// Command getcertgo is a developer utility for fetching, inspecting, and trusting
// remote TLS certificates in Java keystores and OS trust stores.
package main

import (
	"fmt"
	"os"

	"github.com/ravocode/get-cert-go/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}
}
