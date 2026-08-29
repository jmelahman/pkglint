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

	// Rule reference table lists the Fix column, and its header carries the
	// invisible --unsafe-fix sizer that holds the column at one width even in
	// categories with no fixable rules.
	idx := read(filepath.Join("rules", "index.html"))
	if !strings.Contains(idx, `<th>Fix<span class="colsizer">`) {
		t.Errorf("rule reference missing Fix column sizer:\n%s", idx)
	}
}

// TestRenderRuleSeverities covers the Severity column on the rule reference:
// a fixed-severity rule gets one badge, an escalating one gets the range, and
// the header carries the sizer that holds the column at a single width across
// the seven category tables.
func TestRenderRuleSeverities(t *testing.T) {
	// Pin the fixtures' declared severities, so a change to a rule fails here
	// rather than quietly turning the assertions below into no-ops.
	for id, want := range map[string]rules.SeverityRange{
		"PB101": {Low: rules.Error, High: rules.Error},
		"PB302": {Low: rules.Error, High: rules.Critical},
	} {
		r, ok := rules.RuleByID(id)
		if !ok {
			t.Fatalf("rule %s missing from registry", id)
		}
		if got := r.Severities(); got != want {
			t.Fatalf("%s severities = %v, want %v", id, got, want)
		}
	}

	out := t.TempDir()
	for _, sub := range []string{"rules", "package", "badge"} {
		if err := os.MkdirAll(filepath.Join(out, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := renderSite(out, nil); err != nil {
		t.Fatalf("renderSite: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(out, "rules", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	idx := string(b)

	if !strings.Contains(idx, `<th>Severity<span class="colsizer">`) {
		t.Errorf("rule reference missing Severity column sizer:\n%s", idx)
	}
	// PB101 always reports error: one badge, no range.
	const fixed = `<td class="rsev"><span class="sev error">error</span></td>`
	if !strings.Contains(idx, fixed) {
		t.Errorf("PB101 row should carry a single error badge (%s)", fixed)
	}
	// PB302 escalates to critical when the evaluated string is downloaded.
	const ranged = `<td class="rsev"><span class="sev error">error</span>` +
		`<span class="sevto">–</span><span class="sev critical">critical</span></td>`
	if !strings.Contains(idx, ranged) {
		t.Errorf("PB302 row should carry an error–critical range (%s)", ranged)
	}
	// Every rule reports one, so every row has a badge — none may be skipped.
	if got, want := strings.Count(idx, `<td class="rsev">`), len(rules.Registry()); got != want {
		t.Errorf("rule reference has %d severity cells, want %d", got, want)
	}
}

// TestRenderLinkPreview covers the head metadata a link preview reads. The
// failure this guards against is silent: a relative og:image or a page-relative
// og:url renders identically in a browser and produces no card at all when the
// page is posted, and nobody notices until someone shares a link.
func TestRenderLinkPreview(t *testing.T) {
	results := []siteResult{{
		Name: "demo", Base: "demo", Version: "1.0-1", Grade: "A",
		Findings: []rules.Finding{},
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

	// Every page carries the card image and the card type; the canonical URL is
	// the page's own, which is what pins a preview to one address when the same
	// page is reachable as both /rules/ and /rules/index.html.
	for rel, wantURL := range map[string]string{
		"index.html":                          baseURL,
		filepath.Join("rules", "index.html"):  baseURL + "rules/",
		filepath.Join("rules", "PB101.html"):  baseURL + "rules/PB101.html",
		filepath.Join("package", "demo.html"): baseURL + "package/demo.html",
	} {
		b, err := os.ReadFile(filepath.Join(out, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		page := string(b)
		for _, want := range []string{
			`<meta name="twitter:card" content="summary_large_image">`,
			`<meta property="og:image" content="` + baseURL + `assets/og.png">`,
			`<meta property="og:url" content="` + wantURL + `">`,
			`<link rel="canonical" href="` + wantURL + `">`,
		} {
			if !strings.Contains(page, want) {
				t.Errorf("%s missing %s", rel, want)
			}
		}
		// A card with no title or description is a bare link, so the tags have
		// to be filled in rather than merely present.
		for _, empty := range []string{
			`<meta property="og:title" content="">`,
			`<meta property="og:description" content="">`,
			"<title></title>",
		} {
			if strings.Contains(page, empty) {
				t.Errorf("%s has an empty head tag: %s", rel, empty)
			}
		}
	}

	// The image the tags point at has to be published alongside them.
	if _, err := os.Stat(filepath.Join(out, "assets", "og.png")); err != nil {
		t.Errorf("card image not copied to the site: %v", err)
	}
}

// TestRenderMaintainerFilter covers the roster's maintainer search. The roster
// has no maintainer column, so data attributes are the only thing carrying the
// values into the page — and the script that reads them lives in a separate
// file, where renaming either half leaves a page that builds, ships, and
// quietly matches nothing.
func TestRenderMaintainerFilter(t *testing.T) {
	results := []siteResult{
		{Name: "demo", Base: "demo", Version: "1.0-1", Grade: "A", Maintainer: "dbermond", Findings: []rules.Finding{}},
		// Orphaned packages have no maintainer; the AUR drops the field entirely.
		{Name: "orphaned", Base: "orphaned", Version: "2.0-1", Grade: "A", Findings: []rules.Finding{}},
		// A co-maintained package: everyone who can push to it improves it, so
		// everyone who can push to it has to be findable.
		{Name: "shared", Base: "shared", Version: "3.0-1", Grade: "B", Maintainer: "dbermond",
			CoMaintainers: []string{"alice", "bob"}, Findings: []rules.Finding{}},
	}

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

	index := read("index.html")
	for _, want := range []string{
		// What the filter matches on, and the tooltip that lets a row matched on
		// a maintainer say why, given no column shows it.
		`data-maintainer="dbermond"`,
		`title="maintained by dbermond"`,
		// Co-maintainers ride the same way: space-joined in an attribute of
		// their own, and named in the tooltip after the maintainer.
		`data-comaintainers="alice bob"`,
		`title="maintained by dbermond, co-maintained by alice, bob"`,
		// An orphan still carries the attributes, empty, so the script reads a
		// string on every row rather than an undefined on some of them.
		`data-maintainer=""`,
		`data-comaintainers=""`,
		// Nobody searches a field the box does not admit to having.
		`placeholder="Filter by name, maintainer, or description"`,
	} {
		if !strings.Contains(index, want) {
			t.Errorf("index.html missing %s", want)
		}
	}
	// An orphan has no maintainer to name, so it gets no tooltip either.
	if strings.Contains(index, `title="maintained by "`) {
		t.Error("index.html gives an unmaintained package an empty maintainer tooltip")
	}
	// The @ prefix has no other affordance, so the label is the whole of its
	// discoverability.
	if !strings.Contains(index, "Prefix the query with @") {
		t.Error("index.html does not document the @maintainer prefix")
	}

	// The package page names the co-maintainers too: it is where a search for
	// one of them lands, so it has to corroborate what matched.
	if pkg := read(filepath.Join("package", "shared.html")); !strings.Contains(pkg, "co-maintained by alice, bob") {
		t.Errorf("package page does not name the co-maintainers:\n%s", pkg)
	}

	// The other half of the contract: the script has to read the attributes the
	// template writes.
	js := read(filepath.Join("assets", "site.js"))
	for _, want := range []string{"tr.dataset.maintainer", "tr.dataset.comaintainers", `charAt(0) === "@"`} {
		if !strings.Contains(js, want) {
			t.Errorf("site.js missing %s: the roster's maintainer filter is not wired up", want)
		}
	}
}

// TestClip covers the description shortener: previews cut a long description
// wherever they run out of room, so it is cut here on a word instead.
func TestClip(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"short", "PB101: pin it.", 200, "PB101: pin it."},
		{"exact", "abcde", 5, "abcde"},
		{"word boundary", "one two three four", 12, "one two…"},
		{"trailing comma", "one two, three", 9, "one two…"},
		// A dash left stranded by the cut goes with it.
		{"dangling dash", "a — bcdefg", 5, "a…"},
		// Cutting by bytes would end this one mid-rune.
		{"multibyte", "ünïcödé wörd", 7, "ünïcödé…"},
		{"unbroken", "aaaaaaaa", 4, "aaaa…"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clip(tc.in, tc.n); got != tc.want {
				t.Errorf("clip(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}
