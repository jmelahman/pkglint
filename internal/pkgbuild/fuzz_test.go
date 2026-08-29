package pkgbuild

import (
	"os"
	"path/filepath"
	"testing"
)

// seedCorpus feeds every checked-in PKGBUILD fixture to a fuzz target, so
// mutation starts from realistic input instead of noise.
func seedCorpus(f *testing.F) {
	f.Helper()
	matches, err := filepath.Glob(filepath.Join("..", "..", "testdata", "*", "PKGBUILD"))
	if err != nil {
		f.Fatal(err)
	}
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
}

// FuzzParseUnit hammers the PKGBUILD parser — including the rescue path taken
// when bash parsing fails — with hostile input. PKGBUILDs are untrusted input
// that is parsed but never executed, so the parser must return a unit or an
// error, never panic or hang.
func FuzzParseUnit(f *testing.F) {
	seedCorpus(f)
	f.Add([]byte("pkgname=demo\npkgver=1\nbuild() {\n  make\n}\n"))
	// A syntax error up front forces rescueParse to salvage what it can.
	f.Add([]byte("case ,, if do done \x00\nsource=('a')\nsha256sums=('SKIP')\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseUnit("PKGBUILD", raw, false)
	})
}

// FuzzParseScriptlet covers the scriptlet variant, the entry point archive
// analysis uses for the .INSTALL member of a built package.
func FuzzParseScriptlet(f *testing.F) {
	f.Add([]byte("post_install() {\n  true\n}\n"))
	f.Add([]byte("pre_upgrade() { chmod 4755 /usr/bin/x; }"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseScriptlet(".INSTALL", raw)
	})
}

// FuzzParseSrcInfo covers the .SRCINFO parser.
func FuzzParseSrcInfo(f *testing.F) {
	f.Add([]byte("pkgbase = demo\n\tpkgver = 1\n\tsource = https://example.com/x.tar.gz\n\tsha256sums = SKIP\npkgname = demo\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = ParseSrcInfo(raw)
	})
}
