package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmelahman/pkglint/internal/rules"
)

func TestGrade(t *testing.T) {
	f := func(sevs ...rules.Severity) []rules.Finding {
		var out []rules.Finding
		for _, s := range sevs {
			out = append(out, rules.Finding{Severity: s})
		}
		return out
	}
	cases := []struct {
		findings []rules.Finding
		want     string
	}{
		{nil, "A"},
		{f(rules.Info, rules.Info), "A"},
		{f(rules.Warn), "B"},
		{f(rules.Warn, rules.Warn), "B"},
		{f(rules.Warn, rules.Warn, rules.Warn), "C"},
		{f(rules.Error), "D"},
		{f(rules.Warn, rules.Error), "D"},
		{f(rules.Critical, rules.Info), "F"},
	}
	for _, c := range cases {
		if got := Grade(c.findings); got != c.want {
			t.Errorf("Grade(%v) = %q, want %q", c.findings, got, c.want)
		}
	}
}

func TestRenderJSONShape(t *testing.T) {
	r := New("/some/dir/demo", []rules.Finding{{
		RuleID: "PB204", Severity: rules.Warn, Message: "m", Path: "p", Line: 3, Col: 1,
	}})
	var buf bytes.Buffer
	if err := RenderJSON(&buf, []PackageReport{r}); err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if decoded[0]["grade"] != "B" || decoded[0]["name"] != "demo" {
		t.Errorf("unexpected report: %v", decoded[0])
	}
	if !strings.Contains(buf.String(), `"severity": "warn"`) {
		t.Errorf("severity should serialize as its name:\n%s", buf.String())
	}
}

// TestRenderTextSanitizesUntrustedFields is the security proof for SEC5: no raw
// control bytes from PKGBUILD-derived content may reach the terminal.
func TestRenderTextSanitizesUntrustedFields(t *testing.T) {
	r := New("/some/dir/demo", []rules.Finding{{
		RuleID:   "PB204",
		Severity: rules.Warn,
		Message:  "\x1b[31mred\x1b[0m and a\rb",
		Path:     "src/\x1b]0;pwned\x07evil.sh",
		Line:     3,
		Col:      1,
	}})
	var buf bytes.Buffer
	RenderText(&buf, []PackageReport{r}, false)
	out := buf.String()

	for _, bad := range []rune{0x1b, 0x0d, 0x07} {
		if strings.ContainsRune(out, bad) {
			t.Errorf("output contains raw control byte %#x:\n%q", bad, out)
		}
	}
	// The escaped forms must be present, i.e. content is escaped, not dropped.
	for _, want := range []string{`\x1b[31mred`, `a\x0db`, `\x1b]0;pwned\x07evil.sh`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing escaped form %q:\n%q", want, out)
		}
	}
}

// TestRenderTextSanitizesNameAndErr covers the error path's untrusted fields.
func TestRenderTextSanitizesNameAndErr(t *testing.T) {
	r := NewError("pkg\x1b[2Kname", errors.New("boom\rspoofed: grade A, no findings"))
	var buf bytes.Buffer
	RenderText(&buf, []PackageReport{r}, false)
	out := buf.String()

	for _, bad := range []rune{0x1b, 0x0d} {
		if strings.ContainsRune(out, bad) {
			t.Errorf("output contains raw control byte %#x:\n%q", bad, out)
		}
	}
	if !strings.Contains(out, `\x1b[2K`) || !strings.Contains(out, `boom\x0dspoofed`) {
		t.Errorf("name/err not escaped as expected:\n%q", out)
	}
}

// stripSGR removes ANSI SGR sequences (ESC [ … m), the only escapes the
// styler emits.
func stripSGR(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] == ';' || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				i = j
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestStylerTokens(t *testing.T) {
	on := styler(true)
	sevCases := []struct {
		sev  rules.Severity
		want string
	}{
		{rules.Info, "\x1b[36minfo\x1b[0m"},
		{rules.Warn, "\x1b[33mwarn\x1b[0m"},
		{rules.Error, "\x1b[31merror\x1b[0m"},
		{rules.Critical, "\x1b[1;31mcritical\x1b[0m"},
	}
	for _, c := range sevCases {
		if got := on.severity(c.sev); got != c.want {
			t.Errorf("severity(%v) = %q, want %q", c.sev, got, c.want)
		}
	}
	gradeCases := []struct{ grade, want string }{
		{"A", "\x1b[1;32mA\x1b[0m"},
		{"B", "\x1b[32mB\x1b[0m"},
		{"C", "\x1b[33mC\x1b[0m"},
		{"D", "\x1b[31mD\x1b[0m"},
		{"F", "\x1b[1;31mF\x1b[0m"},
		{"?", "\x1b[35m?\x1b[0m"},
	}
	for _, c := range gradeCases {
		if got := on.grade(c.grade); got != c.want {
			t.Errorf("grade(%q) = %q, want %q", c.grade, got, c.want)
		}
	}

	off := styler(false)
	if got := off.severity(rules.Critical); got != "critical" {
		t.Errorf("styler(false).severity = %q, want plain %q", got, "critical")
	}
	if got := off.grade("F"); got != "F" {
		t.Errorf("styler(false).grade = %q, want plain %q", got, "F")
	}
}

// TestRenderTextColor pins that colored output is the plain rendering plus
// SGR sequences — nothing more — and that untrusted content still cannot
// smuggle live escapes in (only pkglint's own SGR codes survive stripping).
func TestRenderTextColor(t *testing.T) {
	reports := []PackageReport{
		New("/some/dir/demo", []rules.Finding{
			{RuleID: "PB204", Severity: rules.Warn, Message: "\x1b[31mred\x1b[0m", Path: "p", Line: 3, Col: 1},
			{RuleID: "PB821", Severity: rules.Error, Message: "member", Path: "usr/bin/x"}, // Line 0: archive finding
		}),
		NewError("broken", errors.New("boom")),
	}
	var colored, plain bytes.Buffer
	RenderText(&colored, reports, true)
	RenderText(&plain, reports, false)

	out := colored.String()
	for _, want := range []string{
		"\x1b[33mwarn\x1b[0m",     // severity with a line
		"\x1b[31merror\x1b[0m",    // severity without a line (archive path)
		"\x1b[2m[PB204]\x1b[0m",   // dim rule ID, brackets included
		"\x1b[31mD\x1b[0m",        // grade
		"\x1b[1;31merror:\x1b[0m", // load-error marker
	} {
		if !strings.Contains(out, want) {
			t.Errorf("colored output missing %q:\n%q", want, out)
		}
	}
	if got := stripSGR(out); got != plain.String() {
		t.Errorf("stripping SGR must yield the plain rendering\n--- stripped ---\n%q\n--- plain ---\n%q", got, plain.String())
	}
	// The finding's own escape sequence must still arrive defused: after
	// removing pkglint's SGR codes, no raw ESC byte may remain.
	if strings.ContainsRune(stripSGR(out), 0x1b) {
		t.Errorf("raw ESC survived outside pkglint's own SGR codes:\n%q", out)
	}
	if !strings.Contains(out, `\x1b[31mred`) {
		t.Errorf("untrusted message not escaped in colored output:\n%q", out)
	}
	if strings.ContainsRune(plain.String(), 0x1b) {
		t.Errorf("plain rendering contains escape codes:\n%q", plain.String())
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"tab\there", "tab here"},              // tabs become spaces
		{"\x1b[31m", `\x1b[31m`},               // ESC
		{"a\rb", `a\x0db`},                     // CR
		{"a\nb", `a\x0ab`},                     // LF inside a field
		{"del\x7f", `del\x7f`},                 // DEL
		{"c1\u0085next", `c1\u0085next`},       // C1 control (NEL)
		{"unicode ok: é ✓", "unicode ok: é ✓"}, // non-control runes untouched
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNewNameResolvesDot locks in C14a: "." and a bare "PKGBUILD" must report
// the containing directory's name, not ".".
func TestNewNameResolvesDot(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Base(cwd)
	for _, path := range []string{".", "./", "PKGBUILD", "./PKGBUILD"} {
		got := New(path, nil).Name
		if got != want {
			t.Errorf("New(%q).Name = %q, want %q", path, got, want)
		}
		if got == "." {
			t.Errorf("New(%q).Name is still \".\"", path)
		}
	}
	// Explicit directories are unaffected by the fallback.
	if got := New("dir/PKGBUILD", nil).Name; got != "dir" {
		t.Errorf(`New("dir/PKGBUILD").Name = %q, want "dir"`, got)
	}
	if got := New("/some/dir/demo", nil).Name; got != "demo" {
		t.Errorf(`New("/some/dir/demo").Name = %q, want "demo"`, got)
	}
	// Root must degrade gracefully rather than panic (STOP-condition check).
	if got := New(string(filepath.Separator), nil).Name; got == "" {
		t.Error("New(root).Name is empty")
	}
}

// TestNewErrorShape locks in C14b: errored packages serialize "findings":[],
// never null.
func TestNewErrorShape(t *testing.T) {
	r := NewError("x", errors.New("boom"))
	if r.Findings == nil {
		t.Error("NewError left Findings nil")
	}
	if r.Grade != "?" || r.Err != "boom" {
		t.Errorf("unexpected grade/err: %q / %q", r.Grade, r.Err)
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, []PackageReport{r}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, `"findings": null`) || strings.Contains(out, `"findings":null`) {
		t.Errorf("errored report serialized findings as null:\n%s", out)
	}
	if !strings.Contains(out, `"findings": []`) {
		t.Errorf("errored report should serialize findings as []:\n%s", out)
	}

	// The name must resolve like New's, not stay ".".
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got := NewError(".", errors.New("boom")).Name; got != filepath.Base(cwd) {
		t.Errorf(`NewError(".").Name = %q, want %q`, got, filepath.Base(cwd))
	}

	// Successful and errored reports must share the same JSON shape.
	var okBuf bytes.Buffer
	if err := RenderJSON(&okBuf, []PackageReport{New("demo", nil)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(okBuf.String(), `"findings": []`) {
		t.Errorf("successful report should also serialize findings as []:\n%s", okBuf.String())
	}
	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if _, ok := decoded[0]["findings"].([]any); !ok {
		t.Errorf("findings did not decode as an array: %#v", decoded[0]["findings"])
	}
}

// renderSARIF renders reports and decodes the output both into the sarif
// structs and into a generic map, so tests can assert on structure without
// string-matching.
func renderSARIF(t *testing.T, reports []PackageReport) (sarifLog, map[string]any, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, reports); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, buf.String())
	}
	var generic map[string]any
	if err := json.Unmarshal(buf.Bytes(), &generic); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, buf.String())
	}
	return log, generic, buf.String()
}

func TestRenderSARIFStructure(t *testing.T) {
	reg := rules.Registry()
	if len(reg) < 2 {
		t.Fatalf("registry has %d rules, need at least 2", len(reg))
	}
	ok := New("/some/dir/demo", []rules.Finding{
		{RuleID: reg[0].ID, Severity: rules.Critical, Message: "boom", Path: "demo/PKGBUILD", Line: 3, Col: 5},
		{RuleID: reg[1].ID, Severity: rules.Info, Message: "fyi", Path: "demo/PKGBUILD", Line: 9, Col: 1},
	})
	bad := NewError("/some/dir/broken", errors.New("parse failed"))

	log, generic, out := renderSARIF(t, []PackageReport{ok, bad})

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
	if log.Schema == "" {
		t.Error("$schema is empty")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "pkglint" {
		t.Errorf("driver name = %q, want %q", run.Tool.Driver.Name, "pkglint")
	}
	if len(run.Tool.Driver.Rules) != len(reg) {
		t.Errorf("driver carries %d rules, want %d (the whole registry)", len(run.Tool.Driver.Rules), len(reg))
	}
	if len(run.Results) != 2 {
		t.Fatalf("got %d results, want 2 (the errored package must not become a result)", len(run.Results))
	}
	for i, res := range run.Results {
		// ruleIndex == -1 would mean a finding from an unregistered rule; the
		// plan calls that out as a condition to investigate, so assert it here.
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("results[%d].ruleIndex = %d, out of range for %d driver rules", i, res.RuleIndex, len(run.Tool.Driver.Rules))
		}
		if got := run.Tool.Driver.Rules[res.RuleIndex].ID; got != res.RuleID {
			t.Errorf("results[%d].ruleIndex points at rule %q, but ruleId is %q", i, got, res.RuleID)
		}
		if len(res.Locations) != 1 {
			t.Fatalf("results[%d] has %d locations, want 1", i, len(res.Locations))
		}
	}
	loc := run.Results[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "demo/PKGBUILD" {
		t.Errorf("uri = %q, want %q", loc.ArtifactLocation.URI, "demo/PKGBUILD")
	}
	if loc.Region.StartLine != 3 || loc.Region.StartColumn != 5 {
		t.Errorf("region = %d:%d, want 3:5", loc.Region.StartLine, loc.Region.StartColumn)
	}
	if run.Results[0].Message.Text != "boom" {
		t.Errorf("message = %q, want %q", run.Results[0].Message.Text, "boom")
	}

	if len(run.Invocations) != 1 {
		t.Fatalf("got %d invocations, want 1", len(run.Invocations))
	}
	inv := run.Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("executionSuccessful should be false when a package failed to load")
	}
	if len(inv.ToolExecutionNotifications) != 1 {
		t.Fatalf("got %d notifications, want 1:\n%s", len(inv.ToolExecutionNotifications), out)
	}
	note := inv.ToolExecutionNotifications[0]
	if note.Level != "error" {
		t.Errorf("notification level = %q, want %q", note.Level, "error")
	}
	if !strings.Contains(note.Message.Text, "/some/dir/broken") || !strings.Contains(note.Message.Text, "parse failed") {
		t.Errorf("notification lost the path or the error: %q", note.Message.Text)
	}

	// SARIF's notification object names its payload "message"; emitting it as
	// "text" is rejected by the 2.1.0 schema (additionalProperties: false).
	rawNote := generic["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)["toolExecutionNotifications"].([]any)[0].(map[string]any)
	if _, ok := rawNote["message"]; !ok {
		t.Errorf("notification has no \"message\" property: %v", rawNote)
	}
	if _, bad := rawNote["text"]; bad {
		t.Errorf("notification carries a bare \"text\" property, which the schema forbids: %v", rawNote)
	}
}

func TestRenderSARIFLevelMapping(t *testing.T) {
	id := rules.Registry()[0].ID
	cases := []struct {
		sev   rules.Severity
		level string
		name  string
	}{
		{rules.Info, "note", "info"},
		{rules.Warn, "warning", "warn"},
		{rules.Error, "error", "error"},
		{rules.Critical, "error", "critical"},
	}
	var findings []rules.Finding
	for _, c := range cases {
		findings = append(findings, rules.Finding{
			RuleID: id, Severity: c.sev, Message: "m", Path: "p", Line: 1, Col: 1,
		})
	}
	log, _, _ := renderSARIF(t, []PackageReport{New("demo", findings)})
	results := log.Runs[0].Results
	if len(results) != len(cases) {
		t.Fatalf("got %d results, want %d", len(results), len(cases))
	}
	for i, c := range cases {
		if results[i].Level != c.level {
			t.Errorf("%v → level %q, want %q", c.sev, results[i].Level, c.level)
		}
		// SARIF collapses critical onto "error", so the pkglint severity has to
		// survive in the properties bag.
		if got := results[i].Properties["severity"]; got != c.name {
			t.Errorf("%v → properties.severity %v, want %q", c.sev, got, c.name)
		}
	}
}

// TestRenderSARIFEmptyResults locks in that a findings-free run serializes
// "results": [] — SARIF consumers reject a null there.
func TestRenderSARIFEmptyResults(t *testing.T) {
	log, generic, out := renderSARIF(t, []PackageReport{New("demo", nil)})
	if len(log.Runs[0].Results) != 0 {
		t.Fatalf("expected no results, got %d", len(log.Runs[0].Results))
	}
	if strings.Contains(out, `"results": null`) {
		t.Errorf("results serialized as null:\n%s", out)
	}
	results, ok := generic["runs"].([]any)[0].(map[string]any)["results"]
	if !ok {
		t.Fatalf("no results key:\n%s", out)
	}
	if _, ok := results.([]any); !ok {
		t.Errorf("results did not decode as an array: %#v", results)
	}
	if !log.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("executionSuccessful should be true when nothing failed to load")
	}
}

// TestRenderSARIFClampsStartLine covers the schema's startLine >= 1 minimum:
// findings without a position must not emit line 0.
func TestRenderSARIFClampsStartLine(t *testing.T) {
	id := rules.Registry()[0].ID
	log, _, _ := renderSARIF(t, []PackageReport{New("demo", []rules.Finding{
		{RuleID: id, Severity: rules.Warn, Message: "m", Path: "p"}, // Line and Col zero
	})})
	region := log.Runs[0].Results[0].Locations[0].PhysicalLocation.Region
	if region.StartLine != 1 {
		t.Errorf("startLine = %d, want 1", region.StartLine)
	}
	if region.StartColumn != 0 {
		t.Errorf("startColumn = %d, want it omitted (0) rather than an invalid 0 in JSON", region.StartColumn)
	}
}

func TestExceedsThreshold(t *testing.T) {
	reports := []PackageReport{New("demo", []rules.Finding{{Severity: rules.Warn}})}
	if ExceedsThreshold(reports, rules.Error) {
		t.Error("warn finding should not exceed error threshold")
	}
	if !ExceedsThreshold(reports, rules.Warn) {
		t.Error("warn finding should exceed warn threshold")
	}
}
