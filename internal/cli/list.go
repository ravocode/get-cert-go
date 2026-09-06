package cli

import (
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravocode/get-cert-go/internal/certs"
	"github.com/ravocode/get-cert-go/internal/keystore"
	"github.com/ravocode/get-cert-go/internal/ui"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [filter]",
		Short: "List trusted certificates in a keystore",
		Long: "List certificates in a keystore (the JVM cacerts by default). An optional\n" +
			"filter matches against alias, common name, or issuer (case-insensitive).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			filter := ""
			if len(args) == 1 {
				filter = strings.ToLower(args[0])
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

			entries, format, err := keystore.Read(keystorePath, password)
			if err != nil {
				ui.Errorf("%v", err)
				return err
			}

			matched := make([]keystore.Entry, 0, len(entries))
			for _, e := range entries {
				if filter == "" || entryMatches(e, filter) {
					matched = append(matched, e)
				}
			}
			sort.Slice(matched, func(i, j int) bool { return matched[i].Alias < matched[j].Alias })

			ui.Infof("Keystore: %s (%s) \u2014 %d of %d entries shown",
				keystorePath, format, len(matched), len(entries))
			if len(matched) == 0 {
				ui.Warnf("No matching entries.")
				return nil
			}
			ui.RenderEntries(matched, time.Now())
			return nil
		},
	}
	return cmd
}

func entryMatches(e keystore.Entry, filterLower string) bool {
	if strings.Contains(strings.ToLower(e.Alias), filterLower) {
		return true
	}
	if strings.Contains(strings.ToLower(certs.CommonName(e.Cert)), filterLower) {
		return true
	}
	return strings.Contains(strings.ToLower(certs.IssuerName(e.Cert)), filterLower)
}
