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

// ANSI SGR sequences RenderText brackets tokens with when color is on.
const (
	ansiReset     = "\x1b[0m"
	ansiBold      = "\x1b[1m"
	ansiDim       = "\x1b[2m"
	ansiRed       = "\x1b[31m"
	ansiGreen     = "\x1b[32m"
	ansiYellow    = "\x1b[33m"
	ansiMagenta   = "\x1b[35m"
	ansiCyan      = "\x1b[36m"
	ansiBoldRed   = "\x1b[1;31m"
	ansiBoldGreen = "\x1b[1;32m"
)

// styler colorizes trusted report tokens; styler(false) passes text through
// unchanged, so plain rendering is byte-identical to the pre-color output.
type styler bool

func (s styler) wrap(code, text string) string {
	if !s {
		return text
	}
	return code + text + ansiReset
}

func (s styler) severity(sev rules.Severity) string {
	var code string
	switch sev {
	case rules.Info:
		code = ansiCyan
	case rules.Warn:
		code = ansiYellow
	case rules.Error:
		code = ansiRed
	default: // Critical
		code = ansiBoldRed
	}
	return s.wrap(code, sev.String())
}

func (s styler) grade(g string) string {
	var code string
	switch g {
	case "A":
		code = ansiBoldGreen
	case "B":
		code = ansiGreen
	case "C":
		code = ansiYellow
	case "D":
		code = ansiRed
	case "F":
		code = ansiBoldRed
	default: // "?" — failed to load
		code = ansiMagenta
	}
	return s.wrap(code, g)
}

// RenderText writes the human-readable report. Untrusted, PKGBUILD-derived
// fields (name, error, path, message) are sanitized; severity, rule ID, and
// grade are trusted enum/registry values. Color is applied only around those
// trusted tokens (and the already-sanitized name), so untrusted content can
// neither carry its own escapes nor break out of ours.
func RenderText(w io.Writer, reports []PackageReport, color bool) {
	s := styler(color)
	for i, r := range reports {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if r.Err != "" {
			fmt.Fprintf(w, "%s: %s %s\n",
				s.wrap(ansiBold, sanitize(r.Name)), s.wrap(ansiBoldRed, "error:"), sanitize(r.Err))
			continue
		}
		fmt.Fprintf(w, "%s: grade %s", s.wrap(ansiBold, sanitize(r.Name)), s.grade(r.Grade))
		if len(r.Findings) == 0 {
			fmt.Fprintf(w, ", no findings\n")
			continue
		}
		fmt.Fprintf(w, ", %d finding(s)\n", len(r.Findings))
		for _, f := range r.Findings {
			if f.Line == 0 {
				// Package-archive findings locate a member, not a line.
				fmt.Fprintf(w, "  %s: %s %s %s\n",
					sanitize(f.Path), s.severity(f.Severity), s.wrap(ansiDim, "["+f.RuleID+"]"), sanitize(f.Message))
				continue
			}
			fmt.Fprintf(w, "  %s:%d:%d: %s %s %s\n",
				sanitize(f.Path), f.Line, f.Col, s.severity(f.Severity), s.wrap(ansiDim, "["+f.RuleID+"]"), sanitize(f.Message))
		}
	}
}

// RenderJSON writes reports as a JSON array.
func RenderJSON(w io.Writer, reports []PackageReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

// SARIF 2.1.0 (https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
// is the interchange format consumed by GitHub code scanning and other tools.
// Only the subset pkglint populates is modeled here.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

// sarifNotification is a notification object: the schema names the payload
// field "message", not "text" (the message object nested inside it is what
// carries "text").
type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// sarifLevel maps a pkglint severity onto SARIF's level enum
// (none|note|warning|error). SARIF has no level above "error", so Critical
// collapses onto it; RenderSARIF preserves the distinction in properties.
func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Info:
		return "note"
	case rules.Warn:
		return "warning"
	default: // Error, Critical
		return "error"
	}
}

// RenderSARIF writes findings in SARIF 2.1.0, suitable for GitHub code
// scanning. Untrusted text needs no sanitizing here: encoding/json escapes
// control characters itself (unlike RenderText, which writes to a terminal).
func RenderSARIF(w io.Writer, reports []PackageReport) error {
	reg := rules.Registry()
	idx := make(map[string]int, len(reg))
	driverRules := make([]sarifRule, len(reg))
	for i, r := range reg {
		idx[r.ID] = i
		driverRules[i] = sarifRule{
			ID:               r.ID,
			Name:             r.Name,
			ShortDescription: sarifText{Text: r.Name},
			FullDescription:  sarifText{Text: r.Doc},
		}
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "pkglint",
			InformationURI: "https://github.com/jmelahman/pkglint",
			Rules:          driverRules,
		}},
		Results:     []sarifResult{}, // non-nil → emits [] not null
		Invocations: []sarifInvocation{{ExecutionSuccessful: true}},
	}

	for _, rep := range reports {
		if rep.Err != "" {
			run.Invocations[0].ExecutionSuccessful = false
			run.Invocations[0].ToolExecutionNotifications = append(
				run.Invocations[0].ToolExecutionNotifications,
				sarifNotification{Level: "error", Message: sarifText{Text: rep.Path + ": " + rep.Err}})
			continue
		}
		for _, f := range rep.Findings {
			ri, ok := idx[f.RuleID]
			if !ok {
				ri = -1 // finding from a rule not in the registry (shouldn't happen)
			}
			line := f.Line
			if line < 1 {
				line = 1 // SARIF requires startLine >= 1
			}
			run.Results = append(run.Results, sarifResult{
				RuleID:    f.RuleID,
				RuleIndex: ri,
				Level:     sarifLevel(f.Severity),
				Message:   sarifText{Text: f.Message},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Path},
					Region:           sarifRegion{StartLine: line, StartColumn: f.Col},
				}}},
				Properties: map[string]any{"severity": f.Severity.String()},
			})
		}
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
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
