package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmelahman/pkglint/internal/rules"
)

// TestRenderFixableBadges renders the site with a mix of fixable and
// non-fixable findings and asserts the auto-fix badges surface on the
// dashboard, the rule reference, and the per-package page.
func TestRenderFixableBadges(t *testing.T) {
	// Sanity-check the fixture rules still classify as expected, so this test
	// fails loudly if a rule's FixLevel changes rather than silently passing.
	for id, want := range map[string]rules.FixLevel{
		"PB101": rules.FixNone,
		"PB203": rules.FixSafe,
		"PB204": rules.FixUnsafe,
	} {
		r, ok := rules.RuleByID(id)
		if !ok {
			t.Fatalf("rule %s missing from registry", id)
		}
		if r.FixLevel != want {
			t.Fatalf("%s FixLevel = %v, want %v", id, r.FixLevel, want)
		}
	}

	results := []siteResult{{
		Name:    "demo",
		Base:    "demo",
		Version: "1.0-1",
		Grade:   "D",
		Findings: []rules.Finding{
			{RuleID: "PB101", Severity: rules.Error, Message: "no checksum", Path: "PKGBUILD", Line: 3},
			{RuleID: "PB203", Severity: rules.Warn, Message: "cargo not locked", Path: "PKGBUILD", Line: 8},
			{RuleID: "PB204", Severity: rules.Warn, Message: "go downloads modules", Path: "PKGBUILD", Line: 9},
		},
	}}

	out := t.TempDir()
	for _, sub := range []string{"rules", "package", "badge"} {
		if err := os.MkdirAll(filepath.Join(out, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := renderSite(out, results); err != nil {
		t.Fatalf("renderSite: %v", err)
	}

	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(out, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}

	// Dashboard: two of three findings are fixable.
	index := read("index.html")
	if !strings.Contains(index, ">2<") || !strings.Contains(index, "auto-fixable") {
		t.Errorf("index.html missing fixable tile (want count 2):\n%s", index)
	}

	// Package page: the fixable findings carry a pill, the non-fixable one does not.
	pkg := read(filepath.Join("package", "demo.html"))
	if strings.Count(pkg, `class="fix `) != 2 {
		t.Errorf("package page should show exactly 2 fix pills, got %d:\n%s",
			strings.Count(pkg, `class="fix `), pkg)
	}
	if !strings.Contains(pkg, ">--fix<") || !strings.Contains(pkg, ">--unsafe-fix<") {
		t.Errorf("package page missing --fix/--unsafe-fix pills:\n%s", pkg)
	}

	// Rule pages: fixable rules advertise the flag, PB101 does not.
	if r := read(filepath.Join("rules", "PB203.html")); !strings.Contains(r, "pkglint --fix") {
		t.Errorf("PB203 rule page missing --fix guidance:\n%s", r)
	}
	if r := read(filepath.Join("rules", "PB204.html")); !strings.Contains(r, "pkglint --unsafe-fix") {
		t.Errorf("PB204 rule page missing --unsafe-fix guidance:\n%s", r)
	}
	if r := read(filepath.Join("rules", "PB101.html")); strings.Contains(r, `class="fix `) {
		t.Errorf("PB101 rule page should not show a fix pill:\n%s", r)
	}

	// Rule reference table lists the Fix column.
	if idx := read(filepath.Join("rules", "index.html")); !strings.Contains(idx, "<th>Fix</th>") {
		t.Errorf("rule reference missing Fix column:\n%s", idx)
	}
}
