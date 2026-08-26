package main

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
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

	for _, r := range results {
		data := map[string]any{"R": r, "Rules": ruleIndex}
		if err := renderTo(tmpl, "package.html", filepath.Join(out, "package", r.Name+".html"), data); err != nil {
			return err
		}
	}
	return nil
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
