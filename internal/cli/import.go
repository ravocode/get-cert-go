package cli

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravocode/get-cert-go/internal/certs"
	"github.com/ravocode/get-cert-go/internal/keystore"
	"github.com/ravocode/get-cert-go/internal/systemstore"
	"github.com/ravocode/get-cert-go/internal/ui"
)

func newImportCmd() *cobra.Command {
	var (
		importAll   bool
		aliasFlag   string
		forceNative bool
		toSystem    bool
		machineWide bool
	)

	cmd := &cobra.Command{
		Use:   "import <url>",
		Short: "Import a remote certificate into a keystore",
		Long: "Fetch a host's certificate chain, let you choose which certificates to\n" +
			"trust, and add them to a Java keystore (the JVM cacerts by default).",
		Args: cobra.ExactArgs(1),
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
			now := time.Now()
			ui.Headingf("\nFound a %d-certificate chain:\n", len(chain))
			ui.RenderChain(chain, now)
			fmt.Println()

			// Decide which certificates to import.
			var selected []int
			switch {
			case importAll:
				for i := range chain {
					selected = append(selected, i)
				}
			default:
				selected, err = ui.SelectCertificates(chain, now)
				if err != nil {
					return err
				}
			}
			if len(selected) == 0 {
				ui.Warnf("No certificates selected; nothing to import.")
				return nil
			}
			if len(selected) > 1 && aliasFlag != "" {
				ui.Warnf("--alias is ignored when importing more than one certificate.")
				aliasFlag = ""
			}

			// OS trust store path: bypass the Java keystore entirely.
			if toSystem {
				return runSystemImport(chain, selected, aliasFlag, machineWide, target.Address())
			}

			keystorePath, err := resolveKeystore()
			if err != nil {
				ui.Errorf("%v", err)
				return err
			}
			password, err := resolvePassword(keystorePath, true)
			if err != nil {
				return err
			}

			format, _ := keystore.DetectFormat(keystorePath)
			ui.Infof("Target keystore: %s (%s)", keystorePath, format)

			var imported int
			for _, idx := range selected {
				cert := chain[idx]
				alias := aliasFlag
				if alias == "" {
					alias = certs.SuggestAlias(cert)
				}

				res, err := keystore.Import(keystorePath, password, alias, cert, forceNative)
				if err != nil {
					ui.Errorf("Failed to import %q: %v", certs.CommonName(cert), err)
					return err
				}
				if res.Warning != "" {
					ui.Warnf("%s", res.Warning)
				}
				ui.Successf("'%s' added to keystore with alias '%s' (via %s).",
					certs.CommonName(cert), res.Alias, res.Method)
				imported++
			}

			if imported > 0 {
				fmt.Println()
				ui.Infof("\U0001f504 Run 'getcertgo doctor %s' to verify local runtime visibility.", target.Address())
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&importAll, "all", false, "import every certificate in the chain without prompting")
	cmd.Flags().StringVar(&aliasFlag, "alias", "", "alias to use (only when importing a single certificate)")
	cmd.Flags().BoolVar(&forceNative, "native", false, "force native Go keystore writing instead of keytool")
	cmd.Flags().BoolVar(&toSystem, "system", false, "import into the OS trust store instead of a Java keystore")
	cmd.Flags().BoolVar(&machineWide, "machine", false, "with --system, target the machine-wide store (needs admin/root)")
	return cmd
}

// runSystemImport installs the selected certificates into the OS trust store.
func runSystemImport(chain []*x509.Certificate, selected []int, aliasFlag string, machineWide bool, address string) error {
	scope := "current-user"
	if machineWide {
		scope = "machine-wide"
	}
	ui.Infof("Target: OS trust store (%s)", scope)

	var installed int
	firefoxNote := false
	for _, idx := range selected {
		cert := chain[idx]
		name := aliasFlag
		if name == "" {
			name = certs.SuggestAlias(cert)
		}

		res, err := systemstore.Install(cert, systemstore.Options{Machine: machineWide, Name: name})
		if err != nil {
			ui.Errorf("Failed to install %q: %v", certs.CommonName(cert), err)
			return err
		}
		ui.Successf("'%s' added to %s.", certs.CommonName(cert), res.Store)
		firefoxNote = firefoxNote || res.FirefoxNote
		installed++
	}

	if installed > 0 {
		fmt.Println()
		if firefoxNote {
			ui.Warnf("Firefox uses its own trust store; enable 'security.enterprise_roots.enabled' in about:config or import there separately.")
		}
		ui.Infof("\U0001f504 Restart your browser, then run 'getcertgo doctor %s' to verify.", address)
	}
	return nil
}
