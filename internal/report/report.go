// Package report aggregates rule findings into graded package reports and
// renders them for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/jmelahman/pkglint/internal/rules"
)

// PackageReport is the lint result for one package.
type PackageReport struct {
	Name     string          `json:"name"`
	Path     string          `json:"path"`
	Grade    string          `json:"grade"`
	Findings []rules.Finding `json:"findings"`
	Err      string          `json:"error,omitempty"`
}

// Grade condenses findings into a letter. The scale is deliberately simple:
// any critical -> F, any error -> D, warns pull an otherwise clean package
// down to B or C, info-only stays A.
func Grade(findings []rules.Finding) string {
	warns := 0
	worst := rules.Info
	for _, f := range findings {
		if f.Severity > worst {
			worst = f.Severity
		}
		if f.Severity == rules.Warn {
			warns++
		}
	}
	switch {
	case worst == rules.Critical:
		return "F"
	case worst == rules.Error:
		return "D"
	case warns >= 3:
		return "C"
	case warns >= 1:
		return "B"
	default:
		return "A"
	}
}

// New builds a report for a package path.
func New(path string, findings []rules.Finding) PackageReport {
	if findings == nil {
		findings = []rules.Finding{}
	}
	name := filepath.Base(path)
	if name == "PKGBUILD" {
		name = filepath.Base(filepath.Dir(path))
	}
	// filepath.Dir(".") is "." again, so a relative path like "." or "PKGBUILD"
	// needs an absolute path to recover the containing directory's name.
	if name == "." || name == string(filepath.Separator) || name == "" {
		if abs, err := filepath.Abs(path); err == nil {
			target := abs
			if filepath.Base(abs) == "PKGBUILD" {
				target = filepath.Dir(abs)
			}
			name = filepath.Base(target)
		}
	}
	return PackageReport{Name: name, Path: path, Grade: Grade(findings), Findings: findings}
}

// NewError builds a report for a package that failed to load. It reuses New's
// name derivation and guarantees a non-nil Findings slice (so JSON emits [] not
// null, consistent with successful reports).
func NewError(path string, loadErr error) PackageReport {
	r := New(path, nil)
	r.Grade = "?"
	r.Err = loadErr.Error()
	return r
}

// sanitize renders untrusted text safe for a terminal by escaping control
// characters, so PKGBUILD-derived content (paths, messages) cannot inject ANSI
// escapes, carriage returns, or title-setting sequences into the report.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.IsControl(r): // C1 controls (U+0080–U+009F), etc.
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RenderText writes the human-readable report. Untrusted, PKGBUILD-derived
// fields (name, error, path, message) are sanitized; severity, rule ID, and
// grade are trusted enum/registry values.
func RenderText(w io.Writer, reports []PackageReport) {
	for i, r := range reports {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if r.Err != "" {
			fmt.Fprintf(w, "%s: error: %s\n", sanitize(r.Name), sanitize(r.Err))
			continue
		}
		fmt.Fprintf(w, "%s: grade %s", sanitize(r.Name), r.Grade)
		if len(r.Findings) == 0 {
			fmt.Fprintf(w, ", no findings\n")
			continue
		}
		fmt.Fprintf(w, ", %d finding(s)\n", len(r.Findings))
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  %s:%d:%d: %s [%s] %s\n",
				sanitize(f.Path), f.Line, f.Col, f.Severity, f.RuleID, sanitize(f.Message))
		}
	}
}

// RenderJSON writes reports as a JSON array.
func RenderJSON(w io.Writer, reports []PackageReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

// ExceedsThreshold reports whether any finding is at or above sev.
func ExceedsThreshold(reports []PackageReport, sev rules.Severity) bool {
	for _, r := range reports {
		if r.Err != "" {
			return true
		}
		for _, f := range r.Findings {
			if f.Severity >= sev {
				return true
			}
		}
	}
	return false
}
