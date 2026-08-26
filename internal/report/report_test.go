package report

import (
	"bytes"
	"encoding/json"
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

func TestExceedsThreshold(t *testing.T) {
	reports := []PackageReport{New("demo", []rules.Finding{{Severity: rules.Warn}})}
	if ExceedsThreshold(reports, rules.Error) {
		t.Error("warn finding should not exceed error threshold")
	}
	if !ExceedsThreshold(reports, rules.Warn) {
		t.Error("warn finding should exceed warn threshold")
	}
}
