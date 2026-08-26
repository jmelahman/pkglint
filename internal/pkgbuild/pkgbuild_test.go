package pkgbuild

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// loadPKGBUILD writes content as a PKGBUILD in a fresh temp dir and loads it,
// mirroring the lint helper in internal/rules/rules_test.go.
func loadPKGBUILD(t *testing.T, content string) *Package {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return pkg
}

// firstWord parses `echo <expr>` with the package's own parser and returns the
// word for <expr>. Going through a real command keeps every word part
// (quoting, expansions, substitutions) exactly as the linter sees it.
func firstWord(t *testing.T, expr string) *syntax.Word {
	t.Helper()
	f, err := newParser().Parse(strings.NewReader("echo "+expr), "test")
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	if len(f.Stmts) != 1 {
		t.Fatalf("parse %q: got %d statements, want 1", expr, len(f.Stmts))
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		t.Fatalf("parse %q: got %T, want *syntax.CallExpr", expr, f.Stmts[0].Cmd)
	}
	if len(call.Args) != 2 {
		t.Fatalf("parse %q: got %d args, want 2", expr, len(call.Args))
	}
	return call.Args[1]
}

// TestRenderWord pins the static-vs-dynamic contract documented on RenderWord.
// It is the linter's core anti-obfuscation guarantee: anything whose value
// cannot be determined statically must render a NUL byte and report dynamic.
func TestRenderWord(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expr    string
		vars    map[string]string
		want    string
		dynamic bool
	}{
		{name: "literal", expr: `hello`, want: "hello"},
		{name: "single quoted", expr: `'single quoted'`, want: "single quoted"},
		{name: "double quoted with unknown ref", expr: `"double $pkgname"`, want: "double $pkgname"},
		{name: "unknown variable", expr: `$unknownvar`, want: "$unknownvar"},
		{name: "braced variable", expr: `${pkgname}`, want: "$pkgname"},
		{name: "concatenated parts", expr: `"$pkgdir/usr/bin"`, want: "$pkgdir/usr/bin"},
		{name: "known variable resolves", expr: `$pkgname`, vars: map[string]string{"pkgname": "demo"}, want: "demo"},
		{name: "known variable braced", expr: `${pkgname}`, vars: map[string]string{"pkgname": "demo"}, want: "demo"},
		{name: "unknown variable with vars map", expr: `$other`, vars: map[string]string{"pkgname": "demo"}, want: "$other"},

		{name: "command substitution", expr: `$(id)`, want: "\x00", dynamic: true},
		{name: "quoted command substitution", expr: `"$(curl x)"`, want: "\x00", dynamic: true},
		{name: "backtick substitution", expr: "`id`", want: "\x00", dynamic: true},
		{name: "process substitution", expr: `<(id)`, want: "\x00", dynamic: true},
		{name: "parameter default", expr: `${x:-default}`, want: "\x00", dynamic: true},
		{name: "parameter length", expr: `${#pkgname}`, want: "\x00", dynamic: true},
		{name: "indirection", expr: `${!pkgname}`, want: "\x00", dynamic: true},
		{name: "slice", expr: `${pkgname:1:2}`, want: "\x00", dynamic: true},
		{name: "replacement", expr: `${pkgname/a/b}`, want: "\x00", dynamic: true},
		{name: "index", expr: `${arr[0]}`, want: "\x00", dynamic: true},
		{name: "arithmetic", expr: `$((1+2))`, want: "\x00", dynamic: true},
		{name: "dynamic wins over static prefix", expr: `"/usr/bin/$(id -u)"`, want: "/usr/bin/\x00", dynamic: true},
		{name: "parameter op is dynamic even with vars", expr: `${pkgname:-x}`, vars: map[string]string{"pkgname": "demo"}, want: "\x00", dynamic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, dynamic := RenderWord(firstWord(t, tc.expr), tc.vars)
			if got != tc.want || dynamic != tc.dynamic {
				t.Errorf("RenderWord(%s) = (%q, %v), want (%q, %v)", tc.expr, got, dynamic, tc.want, tc.dynamic)
			}
		})
	}

	t.Run("nil word", func(t *testing.T) {
		got, dynamic := RenderWord(nil, nil)
		if got != "" || dynamic {
			t.Errorf("RenderWord(nil, nil) = (%q, %v), want (%q, false)", got, dynamic, "")
		}
	})
}

// TestExpandScalar pins variable substitution across top-level scalars.
func TestExpandScalar(t *testing.T) {
	t.Run("plain scalar", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "pkgver=1.0\n")
		got, ok := pkg.Scalar("pkgver")
		if !ok || got != "1.0" {
			t.Errorf("Scalar(pkgver) = (%q, %v), want (%q, true)", got, ok, "1.0")
		}
	})

	t.Run("scalar composed from another scalar", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "_base=foo\npkgname=$_base-bar\n")
		got, ok := pkg.Scalar("pkgname")
		if !ok || got != "foo-bar" {
			t.Errorf("Scalar(pkgname) = (%q, %v), want (%q, true)", got, ok, "foo-bar")
		}
	})

	t.Run("braced reference", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "_base=foo\npkgname=${_base}-bar\n")
		if got := pkg.Expand("${_base}/x"); got != "foo/x" {
			t.Errorf("Expand(${_base}/x) = %q, want %q", got, "foo/x")
		}
	})

	t.Run("unknown reference is left as-is", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "pkgver=1.0\n")
		if got := pkg.Expand("$nope"); got != "$nope" {
			t.Errorf("Expand($nope) = %q, want %q", got, "$nope")
		}
	})

	t.Run("no reference is returned unchanged", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "pkgver=1.0\n")
		if got := pkg.Expand("plain"); got != "plain" {
			t.Errorf("Expand(plain) = %q, want %q", got, "plain")
		}
	})

	t.Run("array is not a scalar", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "arch=('x86_64')\n")
		if got, ok := pkg.Scalar("arch"); ok {
			t.Errorf("Scalar(arch) = (%q, true), want ok=false for an array", got)
		}
	})

	t.Run("missing variable", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "pkgver=1.0\n")
		if got, ok := pkg.Scalar("nope"); ok {
			t.Errorf("Scalar(nope) = (%q, true), want ok=false", got)
		}
	})

	// Mutually recursive scalars must terminate at the fixpoint cap rather than
	// looping forever; the exact residual value is not part of the contract.
	t.Run("self-referential chain terminates", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "a=$b\nb=$a\n")
		got := pkg.Expand("$a")
		if got != "$a" && got != "$b" {
			t.Errorf("Expand($a) = %q, want an unresolved %q or %q", got, "$a", "$b")
		}
	})
}

// TestParseSuppressions pins the inline "# pkglint: ignore=" directive parser.
// Cross-file line collisions are deliberately not covered here.
func TestParseSuppressions(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want map[int]map[string]bool
	}{
		{
			name: "single id on line 3",
			raw:  "pkgname=demo\npkgver=1.0\n# pkglint: ignore=PB204\n",
			want: map[int]map[string]bool{3: {"PB204": true}},
		},
		{
			name: "two ids",
			raw:  "# pkglint: ignore=PB204,PB206\n",
			want: map[int]map[string]bool{1: {"PB204": true, "PB206": true}},
		},
		{
			name: "two ids with spaces",
			raw:  "# pkglint: ignore=PB204, PB206\n",
			want: map[int]map[string]bool{1: {"PB204": true, "PB206": true}},
		},
		{
			name: "trailing directive on a code line",
			raw:  "pkgname=demo # pkglint: ignore=PB101\n",
			want: map[int]map[string]bool{1: {"PB101": true}},
		},
		{
			name: "no directive",
			raw:  "pkgname=demo\n# just a comment\n",
			want: map[int]map[string]bool{},
		},
		{
			name: "lowercase ids are not recognized",
			raw:  "# pkglint: ignore=pb204\n",
			want: map[int]map[string]bool{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSuppressions([]byte(tc.raw)); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseSuppressions(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestSuppressed pins the "same line or the line above" window.
func TestSuppressed(t *testing.T) {
	pkg := loadPKGBUILD(t, "pkgname=demo\n# pkglint: ignore=PB204\npkgver=1.0\n")
	for _, tc := range []struct {
		name string
		id   string
		line int
		want bool
	}{
		{name: "directive line", id: "PB204", line: 2, want: true},
		{name: "line below directive", id: "PB204", line: 3, want: true},
		{name: "line above directive", id: "PB204", line: 1},
		{name: "two lines below directive", id: "PB204", line: 4},
		{name: "other rule id", id: "PB206", line: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pkg.Suppressed(tc.id, tc.line); got != tc.want {
				t.Errorf("Suppressed(%q, %d) = %v, want %v", tc.id, tc.line, got, tc.want)
			}
		})
	}
}

// TestUnits pins that scriptlets referenced by install= are loaded alongside
// the PKGBUILD.
func TestUnits(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"PKGBUILD":     "pkgname=demo\npkgver=1.0\ninstall=demo.install\n",
		"demo.install": "post_install() {\n  echo hi\n}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	units := pkg.Units()
	if len(units) != 2 {
		t.Fatalf("Units() returned %d units, want 2 (PKGBUILD + scriptlet)", len(units))
	}
	if units[0].Scriptlet {
		t.Errorf("first unit should be the PKGBUILD, got %+v", units[0].Path)
	}
	if !units[1].Scriptlet || filepath.Base(units[1].Path) != "demo.install" {
		t.Errorf("second unit should be demo.install, got %q (scriptlet=%v)", units[1].Path, units[1].Scriptlet)
	}
	if _, ok := units[1].Functions["post_install"]; !ok {
		t.Errorf("scriptlet functions = %v, want post_install", units[1].Functions)
	}
}
