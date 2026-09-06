package cli

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/ravocode/get-cert-go/internal/certs"
	"github.com/ravocode/get-cert-go/internal/ui"
)

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <url>",
		Short: "Display a remote certificate chain",
		Long:  "Connect to a host and print a color-coded table of its certificate chain,\nhighlighting expired or soon-to-expire certificates.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			target, err := certs.ParseTarget(args[0])
			if err != nil {
				ui.Errorf("%v", err)
				return err
			}

			ui.Infof("\U0001f512 Connecting to %s ...", target.Address())
			chain, err := certs.FetchChain(target, flagTimeout)
			if err != nil {
				ui.Errorf("%v", err)
				return err
			}

			ui.Headingf("\nFound a %d-certificate chain:\n", len(chain))
			ui.RenderChain(chain, time.Now())
			return nil
		},
	}
}
