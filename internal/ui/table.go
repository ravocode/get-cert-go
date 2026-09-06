package ui

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// cell holds both the display text (which may contain ANSI color codes) and its
// visible width, so that colored cells can be aligned correctly.
type cell struct {
	text  string // possibly colored
	width int    // visible width, excluding ANSI escapes
}

func plain(s string) cell { return cell{text: s, width: len([]rune(s))} }

func colored(s string, c *color.Color) cell {
	return cell{text: c.Sprint(s), width: len([]rune(s))}
}

// printTable renders headers and rows in aligned, padded columns. Column widths
// are computed from the visible width of each cell so ANSI colors do not skew
// alignment.
func printTable(headers []string, rows [][]cell) {
	cols := len(headers)
	widths := make([]int, cols)
	for i, h := range headers {
		widths[i] = len([]rune(h))
	}
	for _, row := range rows {
		for i := 0; i < cols && i < len(row); i++ {
			if row[i].width > widths[i] {
				widths[i] = row[i].width
			}
		}
	}

	// Header
	var b strings.Builder
	for i, h := range headers {
		b.WriteString(bold.Sprint(padRight(h, widths[i])))
		if i < cols-1 {
			b.WriteString("  ")
		}
	}
	fmt.Println(b.String())

	// Separator
	b.Reset()
	for i := 0; i < cols; i++ {
		b.WriteString(dim.Sprint(strings.Repeat("\u2500", widths[i])))
		if i < cols-1 {
			b.WriteString("  ")
		}
	}
	fmt.Println(b.String())

	// Rows
	for _, row := range rows {
		b.Reset()
		for i := 0; i < cols; i++ {
			var c cell
			if i < len(row) {
				c = row[i]
			} else {
				c = plain("")
			}
			pad := widths[i] - c.width
			if pad < 0 {
				pad = 0
			}
			b.WriteString(c.text)
			b.WriteString(strings.Repeat(" ", pad))
			if i < cols-1 {
				b.WriteString("  ")
			}
		}
		fmt.Println(b.String())
	}
}

func padRight(s string, w int) string {
	n := w - len([]rune(s))
	if n <= 0 {
		return s
	}
	return s + strings.Repeat(" ", n)
}
