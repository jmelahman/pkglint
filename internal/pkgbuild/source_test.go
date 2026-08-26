package pkgbuild

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestExpandBraces(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"plain.tar.gz", []string{"plain.tar.gz"}},
		{"foo.tar.gz{,.sig}", []string{"foo.tar.gz", "foo.tar.gz.sig"}},
		{"foo.{tar.gz,zip}", []string{"foo.tar.gz", "foo.zip"}},
		{"a{1,2}b{3,4}", []string{"a1b3", "a1b4", "a2b3", "a2b4"}},
		{"${_tar}", []string{"${_tar}"}},                       // parameter braces, not a group
		{"${_tar}{,.asc}", []string{"${_tar}", "${_tar}.asc"}}, // mixed
		{"nocomma{x}", []string{"nocomma{x}"}},                 // bash leaves this literal too
	} {
		if got := expandBraces(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("expandBraces(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSourcesBraceExpansion(t *testing.T) {
	dir := t.TempDir()
	content := `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
_tar=demo-$pkgver.tar.gz
source=("https://example.com/$_tar{,.sig}")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' 'SKIP')
`
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	srcs := pkg.Sources()
	if len(srcs) != 2 {
		t.Fatalf("expected 2 expanded sources, got %d: %+v", len(srcs), srcs)
	}
	if srcs[0].URL != "https://example.com/demo-1.0.0.tar.gz" || srcs[0].Index != 0 {
		t.Errorf("first source wrong: %+v", srcs[0])
	}
	if srcs[1].URL != "https://example.com/demo-1.0.0.tar.gz.sig" || srcs[1].Index != 1 {
		t.Errorf("second source wrong: %+v", srcs[1])
	}
	// Checksums pair by expanded index, exactly as makepkg pairs them.
	if sums := pkg.SumsFor(srcs[1]); len(sums) != 1 || sums[0] != "SKIP" {
		t.Errorf("sig source should pair with the SKIP sum, got %v", sums)
	}
}

// TestParseSourceEntry pins makepkg's [filename::]url[#fragment][?query]
// splitting for the well-defined orderings.
func TestParseSourceEntry(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		filename string
		url      string
		proto    string
		vcs      string
		fragment map[string]string
		query    string
		local    bool
	}{
		{
			name:     "plain https tarball",
			raw:      "https://example.com/foo.tar.gz",
			url:      "https://example.com/foo.tar.gz",
			proto:    "https",
			fragment: map[string]string{},
		},
		{
			name:     "plain http tarball",
			raw:      "http://example.com/x.tar.gz",
			url:      "http://example.com/x.tar.gz",
			proto:    "http",
			fragment: map[string]string{},
		},
		{
			name:     "explicit filename",
			raw:      "foo.tar.gz::https://example.com/x.tar.gz",
			filename: "foo.tar.gz",
			url:      "https://example.com/x.tar.gz",
			proto:    "https",
			fragment: map[string]string{},
		},
		{
			name:     "vcs proto",
			raw:      "git+https://github.com/example/foo.git",
			url:      "git+https://github.com/example/foo.git",
			proto:    "git+https",
			vcs:      "git",
			fragment: map[string]string{},
		},
		{
			name:     "bare vcs proto",
			raw:      "git://github.com/example/foo.git",
			url:      "git://github.com/example/foo.git",
			proto:    "git",
			vcs:      "git",
			fragment: map[string]string{},
		},
		{
			name:     "vcs with commit fragment",
			raw:      "git+https://github.com/example/foo.git#commit=abc123",
			url:      "git+https://github.com/example/foo.git",
			proto:    "git+https",
			vcs:      "git",
			fragment: map[string]string{"commit": "abc123"},
		},
		{
			// Canonical makepkg order. Guard against regressing the common
			// case while making the reversed order work.
			name:     "fragment then query",
			raw:      "git+https://x/y.git#tag=v1?signed",
			url:      "git+https://x/y.git",
			proto:    "git+https",
			vcs:      "git",
			fragment: map[string]string{"tag": "v1"},
			query:    "signed",
		},
		{
			// The reversed order used to swallow the whole "#commit=abc" into
			// Query, leaving Fragment empty — so a commit-pin check saw an
			// unpinned VCS source and misfired.
			name:     "query then fragment",
			raw:      "git+https://x/y.git?signed#commit=abc",
			url:      "git+https://x/y.git",
			proto:    "git+https",
			vcs:      "git",
			fragment: map[string]string{"commit": "abc"},
			query:    "signed",
		},
		{
			name:     "query only",
			raw:      "git+https://x/y.git?signed",
			url:      "git+https://x/y.git",
			proto:    "git+https",
			vcs:      "git",
			fragment: map[string]string{},
			query:    "signed",
		},
		{
			name:     "fragment only",
			raw:      "git+https://x/y.git#branch=main",
			url:      "git+https://x/y.git",
			proto:    "git+https",
			vcs:      "git",
			fragment: map[string]string{"branch": "main"},
		},
		{
			// Pathological, not valid makepkg input. Pinned only to prove the
			// tail loop consumes one delimiter per iteration and terminates:
			// the URL stops at the first delimiter, valueless "#b"/"#c"
			// segments add no fragment, and the last query wins.
			name:     "repeated delimiters terminate",
			raw:      "a#b#c?d?e",
			url:      "a",
			local:    true,
			fragment: map[string]string{},
			query:    "e",
		},
		{
			name:     "proto is lowercased",
			raw:      "HTTPS://example.com/x.tar.gz",
			url:      "HTTPS://example.com/x.tar.gz",
			proto:    "https",
			fragment: map[string]string{},
		},
		{
			name:     "local file",
			raw:      "local-file.patch",
			url:      "local-file.patch",
			local:    true,
			fragment: map[string]string{},
		},
		{
			name:     "local file with explicit name",
			raw:      "renamed.patch::local-file.patch",
			filename: "renamed.patch",
			url:      "local-file.patch",
			local:    true,
			fragment: map[string]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := parseSourceEntry(tc.raw, tc.raw)
			if e.Raw != tc.raw || e.Expanded != tc.raw {
				t.Errorf("Raw/Expanded = %q/%q, want %q", e.Raw, e.Expanded, tc.raw)
			}
			if e.Filename != tc.filename {
				t.Errorf("Filename = %q, want %q", e.Filename, tc.filename)
			}
			if e.URL != tc.url {
				t.Errorf("URL = %q, want %q", e.URL, tc.url)
			}
			if e.Proto != tc.proto {
				t.Errorf("Proto = %q, want %q", e.Proto, tc.proto)
			}
			if e.VCS != tc.vcs {
				t.Errorf("VCS = %q, want %q", e.VCS, tc.vcs)
			}
			if !reflect.DeepEqual(e.Fragment, tc.fragment) {
				t.Errorf("Fragment = %v, want %v", e.Fragment, tc.fragment)
			}
			if e.Query != tc.query {
				t.Errorf("Query = %q, want %q", e.Query, tc.query)
			}
			if e.Local != tc.local {
				t.Errorf("Local = %v, want %v", e.Local, tc.local)
			}
		})
	}
}

// TestSourcePositions pins that each entry carries its own written element's
// position. Every entry used to report the position of the `source=(` token,
// so a finding about the third source pointed at the first line of the array.
func TestSourcePositions(t *testing.T) {
	t.Run("one element per line", func(t *testing.T) {
		// `source=(` opens on line 3; the three elements sit on lines 3, 4, 5,
		// each indented to column 9.
		pkg := loadPKGBUILD(t, `pkgname=demo
pkgver=1.0.0
source=("https://example.com/a.tar.gz"
        "https://example.com/b.tar.gz"
        "https://example.com/c.tar.gz")
`)
		srcs := pkg.Sources()
		if len(srcs) != 3 {
			t.Fatalf("Sources() = %d entries, want 3: %+v", len(srcs), srcs)
		}
		for i, want := range []struct{ line, col uint }{{3, 9}, {4, 9}, {5, 9}} {
			if got := srcs[i].Pos; got.Line() != want.line || got.Col() != want.col {
				t.Errorf("Sources()[%d] (%s) at %d:%d, want %d:%d",
					i, srcs[i].URL, got.Line(), got.Col(), want.line, want.col)
			}
		}
	})

	t.Run("brace expansion shares the element position", func(t *testing.T) {
		// Both expansions come from one written element, so both report it:
		// they genuinely occupy the same source line.
		pkg := loadPKGBUILD(t, `pkgname=demo
source=("https://example.com/a.tar.gz"
        "https://example.com/b.tar.gz"{,.sig})
`)
		srcs := pkg.Sources()
		if len(srcs) != 3 {
			t.Fatalf("Sources() = %d entries, want 3: %+v", len(srcs), srcs)
		}
		for i, want := range []struct{ line, col uint }{{2, 9}, {3, 9}, {3, 9}} {
			if got := srcs[i].Pos; got.Line() != want.line || got.Col() != want.col {
				t.Errorf("Sources()[%d] (%s) at %d:%d, want %d:%d",
					i, srcs[i].URL, got.Line(), got.Col(), want.line, want.col)
			}
		}
	})

	t.Run("appended elements fall back to the array position", func(t *testing.T) {
		// A merged `+=` Var keeps the first assignment's Assign, so appended
		// values have no AST element to take a position from. They report the
		// base array's position rather than a wrong one — the accepted
		// limitation of merging appends.
		pkg := loadPKGBUILD(t, `pkgname=demo
source=("https://example.com/a.tar.gz")
source+=("https://example.com/b.tar.gz")
`)
		srcs := pkg.Sources()
		if len(srcs) != 2 {
			t.Fatalf("Sources() = %d entries, want 2: %+v", len(srcs), srcs)
		}
		if got := srcs[0].Pos; got.Line() != 2 || got.Col() != 9 {
			t.Errorf("base element at %d:%d, want 2:9", got.Line(), got.Col())
		}
		if got := srcs[1].Pos; got.Line() != 2 || got.Col() != 1 {
			t.Errorf("appended element at %d:%d, want the array position 2:1", got.Line(), got.Col())
		}
	})

	t.Run("scalar source keeps the assignment position", func(t *testing.T) {
		// A scalar `source=` has no Array, so there is no element to index.
		pkg := loadPKGBUILD(t, `pkgname=demo
source=https://example.com/a.tar.gz
`)
		srcs := pkg.Sources()
		if len(srcs) != 1 {
			t.Fatalf("Sources() = %d entries, want 1: %+v", len(srcs), srcs)
		}
		if got := srcs[0].Pos; got.Line() != 2 || got.Col() != 1 {
			t.Errorf("scalar source at %d:%d, want 2:1", got.Line(), got.Col())
		}
	})
}

// TestSourceEntryHost pins hostname extraction, including the VCS prefix strip.
func TestSourceEntryHost(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"https://Example.COM/foo.tar.gz", "example.com"},
		{"git+https://github.com/example/foo.git", "github.com"},
		{"local-file.patch", ""},
	} {
		if got := parseSourceEntry(tc.raw, tc.raw).Host(); got != tc.want {
			t.Errorf("Host(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestChecksums pins how sums arrays are collected per arch and paired with
// source entries by index.
func TestChecksums(t *testing.T) {
	t.Run("base arrays pair by index", func(t *testing.T) {
		pkg := loadPKGBUILD(t, `pkgname=demo
pkgver=1.0.0
source=('a.tar.gz' 'b.tar.gz')
sha256sums=('aaaa' 'bbbb')
`)
		sums := pkg.Checksums("")
		if !reflect.DeepEqual(sums, map[string][]string{"sha256": {"aaaa", "bbbb"}}) {
			t.Fatalf(`Checksums("") = %v, want {sha256: [aaaa bbbb]}`, sums)
		}
		srcs := pkg.Sources()
		if len(srcs) != 2 {
			t.Fatalf("Sources() = %d entries, want 2", len(srcs))
		}
		for i, want := range []string{"aaaa", "bbbb"} {
			if got := pkg.SumsFor(srcs[i]); !reflect.DeepEqual(got, []string{want}) {
				t.Errorf("SumsFor(index %d) = %v, want [%s]", i, got, want)
			}
		}
	})

	t.Run("multiple algorithms", func(t *testing.T) {
		pkg := loadPKGBUILD(t, `pkgname=demo
source=('a.tar.gz')
md5sums=('mmmm')
sha256sums=('aaaa')
`)
		sums := pkg.Checksums("")
		if !reflect.DeepEqual(sums, map[string][]string{"md5": {"mmmm"}, "sha256": {"aaaa"}}) {
			t.Fatalf(`Checksums("") = %v, want {md5: [mmmm], sha256: [aaaa]}`, sums)
		}
		got := pkg.SumsFor(pkg.Sources()[0])
		sort.Strings(got) // SumsFor iterates a map; order is not part of the contract
		if !reflect.DeepEqual(got, []string{"aaaa", "mmmm"}) {
			t.Errorf("SumsFor = %v, want [aaaa mmmm]", got)
		}
	})

	t.Run("arch-suffixed arrays", func(t *testing.T) {
		pkg := loadPKGBUILD(t, `pkgname=demo
source_x86_64=('a.tar.gz')
sha256sums_x86_64=('cccc')
`)
		if sums := pkg.Checksums("x86_64"); !reflect.DeepEqual(sums, map[string][]string{"sha256": {"cccc"}}) {
			t.Fatalf(`Checksums("x86_64") = %v, want {sha256: [cccc]}`, sums)
		}
		if sums := pkg.Checksums(""); len(sums) != 0 {
			t.Errorf(`Checksums("") = %v, want empty`, sums)
		}
		srcs := pkg.Sources()
		if len(srcs) != 1 || srcs[0].Arch != "x86_64" {
			t.Fatalf("Sources() = %+v, want one entry with Arch=x86_64", srcs)
		}
		if got := pkg.SumsFor(srcs[0]); !reflect.DeepEqual(got, []string{"cccc"}) {
			t.Errorf("SumsFor = %v, want [cccc]", got)
		}
	})

	t.Run("missing sum for index yields none", func(t *testing.T) {
		pkg := loadPKGBUILD(t, `pkgname=demo
source=('a.tar.gz' 'b.tar.gz')
sha256sums=('aaaa')
`)
		srcs := pkg.Sources()
		if got := pkg.SumsFor(srcs[1]); len(got) != 0 {
			t.Errorf("SumsFor(index 1) = %v, want none", got)
		}
	})
}
