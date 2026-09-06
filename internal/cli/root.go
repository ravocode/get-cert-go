// Package cli wires up the cobra command tree for the getcertgo tool.
package cli

import (
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Persistent flags shared across commands.
var (
	flagKeystore string
	flagPassword string
	flagTimeout  time.Duration
	flagNoColor  bool
)

// NewRootCmd builds the root command and attaches all subcommands.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "getcertgo",
		Short: "Fetch, inspect, and trust remote TLS certificates",
		Long: "getcertgo is a developer utility for pulling remote certificate chains,\n" +
			"diagnosing TLS/SSL issues, and importing certificates into Java\n" +
			"keystores (JKS/PKCS12) or listing what is already trusted.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if flagNoColor {
				color.NoColor = true
			}
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true

	root.PersistentFlags().StringVar(&flagKeystore, "keystore", "", "path to keystore (defaults to the JVM cacerts)")
	root.PersistentFlags().StringVar(&flagPassword, "password", "", "keystore password (default: prompt, falls back to 'changeit')")
	root.PersistentFlags().DurationVar(&flagTimeout, "timeout", 10*time.Second, "connection timeout")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colored output")

	root.AddCommand(
		newInspectCmd(),
		newImportCmd(),
		newListCmd(),
		newDoctorCmd(),
	)
	return root
}
