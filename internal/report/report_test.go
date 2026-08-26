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
	RenderText(&buf, []PackageReport{r})
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
	RenderText(&buf, []PackageReport{r})
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

func TestExceedsThreshold(t *testing.T) {
	reports := []PackageReport{New("demo", []rules.Finding{{Severity: rules.Warn}})}
	if ExceedsThreshold(reports, rules.Error) {
		t.Error("warn finding should not exceed error threshold")
	}
	if !ExceedsThreshold(reports, rules.Warn) {
		t.Error("warn finding should exceed warn threshold")
	}
}
