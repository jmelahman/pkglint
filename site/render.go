package main

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jmelahman/pkglint/internal/rules"
)

//go:embed templates/*.html
var templateFS embed.FS

var funcs = template.FuncMap{
	"sev": func(s rules.Severity) string { return s.String() },
}

func renderSite(out string, results []siteResult) error {
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return err
	}

	counts := map[string]int{}
	findingsTotal := 0
	for _, r := range results {
		counts[r.Grade]++
		findingsTotal += len(r.Findings)
	}
	indexData := map[string]any{
		"Results":   results,
		"Counts":    counts,
		"Grades":    []string{"A", "B", "C", "D", "F", "?"},
		"Total":     len(results),
		"Findings":  findingsTotal,
		"Generated": time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	}
	if err := renderTo(tmpl, "index.html", filepath.Join(out, "index.html"), indexData); err != nil {
		return err
	}

	ruleIndex := map[string]rules.Rule{}
	for _, r := range rules.Registry() {
		ruleIndex[r.ID] = r
		data := map[string]any{"Rule": r}
		if err := renderTo(tmpl, "rule.html", filepath.Join(out, "rules", r.ID+".html"), data); err != nil {
			return err
		}
	}

	rulesData := map[string]any{"Groups": groupRules(rules.Registry())}
	if err := renderTo(tmpl, "rulesindex.html", filepath.Join(out, "rules", "index.html"), rulesData); err != nil {
		return err
	}

	for _, r := range results {
		data := map[string]any{"R": r, "Rules": ruleIndex}
		if err := renderTo(tmpl, "package.html", filepath.Join(out, "package", r.Name+".html"), data); err != nil {
			return err
		}
	}
	return nil
}

// ruleGroup is a titled section of the rule reference.
type ruleGroup struct {
	Title string
	Rules []rules.Rule
}

// groupRules buckets the registry by the PB-hundreds prefix (PB1xx, PB2xx, …),
// in ID order. Registry() already returns rules sorted by ID.
func groupRules(all []rules.Rule) []ruleGroup {
	titles := []struct {
		prefix string
		title  string
	}{
		{"PB1", "PB1xx — Integrity & provenance"},
		{"PB2", "PB2xx — Hermeticity"},
		{"PB3", "PB3xx — Execution & obfuscation"},
		{"PB4", "PB4xx — Filesystem & privilege"},
		{"PB5", "PB5xx — Install scriptlets"},
		{"PB6", "PB6xx — Metadata consistency"},
	}
	var groups []ruleGroup
	for _, t := range titles {
		g := ruleGroup{Title: t.title}
		for _, r := range all {
			if strings.HasPrefix(r.ID, t.prefix) {
				g.Rules = append(g.Rules, r)
			}
		}
		if len(g.Rules) > 0 {
			groups = append(groups, g)
		}
	}
	return groups
}

func renderTo(tmpl *template.Template, name, path string, data any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := tmpl.ExecuteTemplate(f, name, data); err != nil {
		return fmt.Errorf("render %s: %w", name, err)
	}
	return nil
}
