package ui

import (
	"fmt"
	"time"

	"github.com/ravocode/get-cert-go/internal/certs"
	"github.com/ravocode/get-cert-go/internal/keystore"
)

// RenderEntries prints a table of keystore entries.
func RenderEntries(entries []keystore.Entry, now time.Time) {
	headers := []string{"ALIAS", "COMMON NAME", "ISSUER", "VALID TO", "STATUS"}
	rows := make([][]cell, 0, len(entries))
	for _, e := range entries {
		status, desc := certs.Expiry(e.Cert, now)
		rows = append(rows, []cell{
			plain(truncate(e.Alias, 34)),
			plain(truncate(certs.CommonName(e.Cert), 36)),
			plain(truncate(certs.IssuerName(e.Cert), 36)),
			plain(e.Cert.NotAfter.Format("2006-01-02")),
			statusCell(status, desc),
		})
	}
	fmt.Println()
	printTable(headers, rows)
}
