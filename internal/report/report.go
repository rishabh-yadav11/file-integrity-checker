// Package report renders check/update results as colored text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// ANSI colors.
const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
)

// Options controls rendering.
type Options struct {
	Format string // "text" (default) or "json"
	Color  bool   // colorize text output
	Quiet  bool   // hide Unmodified lines
}

// Summary aggregates results by kind.
type Summary struct {
	Unmodified int `json:"unmodified"`
	Modified   int `json:"modified"`
	New        int `json:"new"`
	Missing    int `json:"missing"`
}

// Count tallies results into a Summary.
func Count(results []model.Result) Summary {
	var s Summary
	for _, r := range results {
		switch r.Kind {
		case model.KindUnmodified:
			s.Unmodified++
		case model.KindModified:
			s.Modified++
		case model.KindNew:
			s.New++
		case model.KindMissing:
			s.Missing++
		}
	}
	return s
}

// Changed reports whether any result is not Unmodified.
func (s Summary) Changed() bool { return s.Modified+s.New+s.Missing > 0 }

// Total is the number of files considered.
func (s Summary) Total() int { return s.Unmodified + s.Modified + s.New + s.Missing }

// Text renders the human-readable trailing summary line.
func (s Summary) Text() string {
	return fmt.Sprintf(
		"summary: %d unmodified, %d modified, %d new, %d missing (%d files)",
		s.Unmodified, s.Modified, s.New, s.Missing, s.Total(),
	)
}

// Render writes results to w in the configured format, sorted by path.
// The caller's slice is never mutated (sorted on a copy).
func Render(w io.Writer, results []model.Result, opts Options) error {
	sorted := make([]model.Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	if opts.Format == "json" {
		return renderJSON(w, sorted)
	}
	return renderText(w, sorted, opts)
}

func renderJSON(w io.Writer, results []model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Reasons carry "->" (e.g. "size 3 -> 9"); the default encoder escapes
	// '>' and '<' to \u003e/\u003c, corrupting the diff text (M6).
	enc.SetEscapeHTML(false)
	return enc.Encode(struct {
		Results []model.Result `json:"results"`
	}{Results: results})
}

func renderText(w io.Writer, results []model.Result, opts Options) error {
	for _, r := range results {
		if opts.Quiet && r.Kind == model.KindUnmodified {
			continue
		}
		if err := writeLine(w, r, opts.Color); err != nil {
			return err
		}
	}
	return nil
}

// display renders a path for text output, quoting it with strconv.Quote
// when it contains control characters (e.g. a newline) so the line
// cannot be broken or forged.
func display(p string) string {
	if strings.ContainsAny(p, "\r\n") {
		return strconv.Quote(p)
	}
	return p
}

func writeLine(w io.Writer, r model.Result, color bool) error {
	reason := ""
	if len(r.Reasons) > 0 {
		reason = fmt.Sprintf(" (%s)", strings.Join(r.Reasons, ", "))
	}
	switch r.Kind {
	case model.KindUnmodified:
		if color {
			_, err := fmt.Fprintf(w, "%sUNMODIFIED%s %s\n", cGreen, cReset, display(r.Path))
			return err
		}
		_, err := fmt.Fprintf(w, "UNMODIFIED %s\n", display(r.Path))
		return err
	case model.KindModified:
		return writeTagged(w, color, cRed, "MODIFIED", display(r.Path), reason)
	case model.KindNew:
		return writeTagged(w, color, cYellow, "NEW", display(r.Path), reason)
	case model.KindMissing:
		return writeTagged(w, color, cRed, "MISSING", display(r.Path), reason)
	default:
		return fmt.Errorf("unknown change kind %q", r.Kind)
	}
}

func writeTagged(w io.Writer, color bool, code, tag, path, reason string) error {
	if color {
		_, err := fmt.Fprintf(w, "%s%s%s %s%s\n", code, tag, cReset, path, reason)
		return err
	}
	_, err := fmt.Fprintf(w, "%s %s%s\n", tag, path, reason)
	return err
}
