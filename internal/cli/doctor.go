package cli

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/spf13/cobra"

	"github.com/ravocode/get-cert-go/internal/certs"
	"github.com/ravocode/get-cert-go/internal/keystore"
	"github.com/ravocode/get-cert-go/internal/systemstore"
	"github.com/ravocode/get-cert-go/internal/ui"
)

func newDoctorCmd() *cobra.Command {
	var useSystem bool
	cmd := &cobra.Command{
		Use:   "doctor <url>",
		Short: "Verify a host validates against trust anchors",
		Long: "Attempt a real, verifying TLS handshake to a host using trust anchors from\n" +
			"either the JVM cacerts keystore (default) or the OS trust store with --system.\n" +
			"Use it to confirm that a certificate you imported makes the host trusted.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			target, err := certs.ParseTarget(args[0])
			if err != nil {
				ui.Errorf("%v", err)
				return err
			}

			pool, source, err := trustPool(useSystem)
			if err != nil {
				ui.Errorf("%v", err)
				return err
			}
			ui.Infof("Using trust anchors from %s", source)

			ui.Infof("\U0001f512 Verifying %s ...", target.Address())
			dialer := &net.Dialer{Timeout: flagTimeout}
			conf := &tls.Config{RootCAs: pool, ServerName: target.Host}
			conn, err := tls.DialWithDialer(dialer, "tcp", target.Address(), conf)
			if err != nil {
				ui.Errorf("Not trusted: %v", err)
				ui.Infof("\U0001f4a1 Run 'getcertgo import %s' to add the missing certificate.", target.Address())
				return err
			}
			_ = conn.Close()

			ui.Successf("%s is trusted by this keystore.", target.Address())
			return nil
		},
	}
	cmd.Flags().BoolVar(&useSystem, "system", false, "verify using the OS trust store instead of a Java keystore")
	return cmd
}

func trustPool(useSystem bool) (*x509.CertPool, string, error) {
	if useSystem {
		pool, source, err := systemstore.SystemRootPool()
		if err != nil {
			return nil, "", err
		}
		return pool, source, nil
	}

	keystorePath, err := resolveKeystore()
	if err != nil {
		return nil, "", err
	}
	password, err := resolvePassword(keystorePath, true)
	if err != nil {
		return nil, "", err
	}

	entries, format, err := keystore.Read(keystorePath, password)
	if err != nil {
		return nil, "", err
	}

	pool := x509.NewCertPool()
	for _, e := range entries {
		pool.AddCert(e.Cert)
	}
	return pool, keystorePath + " (" + format.String() + ")", nil
}
