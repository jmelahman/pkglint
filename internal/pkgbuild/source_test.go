package pkgbuild

import (
	"os"
	"path/filepath"
	"reflect"
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
