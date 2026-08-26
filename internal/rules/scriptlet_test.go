package rules

import (
	"strings"
	"testing"
)

// A scriptlet that fails to parse is walked by no rule, so the parse failure
// itself has to be reported (PB503) rather than silently dropped.
func TestScriptletParseErrorReported(t *testing.T) {
	t.Run("PB503 unparseable scriptlet", func(t *testing.T) {
		expectRule(t, "PB503", map[string]string{
			"PKGBUILD":    pkgbuildWith("", "install=foo.install"),
			"foo.install": "post_install() {\n  echo hi\n# no closing brace\n",
		})
	})

	t.Run("PB503 not for a well-formed scriptlet", func(t *testing.T) {
		expectNoRule(t, "PB503", map[string]string{
			"PKGBUILD":    pkgbuildWith("", "install=foo.install"),
			"foo.install": "post_install() {\n  echo hi\n}\n",
		})
	})

	t.Run("PB503 not when there is no scriptlet at all", func(t *testing.T) {
		expectNoRule(t, "PB503", map[string]string{"PKGBUILD": cleanPKGBUILD})
	})

	t.Run("finding names the scriptlet and the parse error", func(t *testing.T) {
		var got *Finding
		for _, f := range lint(t, map[string]string{
			"PKGBUILD":    pkgbuildWith("", "install=foo.install"),
			"foo.install": "post_install() {\n  echo hi\n# no closing brace\n",
		}) {
			if f.RuleID == "PB503" {
				got = &f
				break
			}
		}
		if got == nil {
			t.Fatal("expected a PB503 finding")
		}
		if !strings.HasSuffix(got.Path, "foo.install") {
			t.Errorf("path = %q, want it to end in foo.install", got.Path)
		}
		if got.Severity != Error {
			t.Errorf("severity = %v, want error", got.Severity)
		}
		if !strings.Contains(got.Message, "could not be parsed") {
			t.Errorf("message = %q, want it to mention the parse failure", got.Message)
		}
	})
}
