package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
)

// fixAll writes files to a temp dir, runs Fix at the given level, and returns
// the fixed content of each changed unit keyed by base filename.
func fixAll(t *testing.T, files map[string]string, level FixLevel, env *FixEnv) map[string]string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg, err := pkgbuild.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out := map[string]string{}
	for _, r := range Fix(pkg, nil, level, env) {
		if r.Changed() {
			out[filepath.Base(r.Path)] = string(r.Fixed)
		}
	}
	return out
}

// fixPKGBUILD is a convenience for the common single-file case.
func fixPKGBUILD(t *testing.T, body string, level FixLevel, env *FixEnv) string {
	t.Helper()
	return fixAll(t, map[string]string{"PKGBUILD": pkgbuildWith("", body)}, level, env)["PKGBUILD"]
}

func fakeResolve(_, _ string) (string, error) {
	return "0123456789abcdef0123456789abcdef01234567", nil
}

func mustContain(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("expected output to contain %q\n--- got ---\n%s", want, got)
	}
}

func mustNotContain(t *testing.T, got, want string) {
	t.Helper()
	if strings.Contains(got, want) {
		t.Errorf("expected output NOT to contain %q\n--- got ---\n%s", want, got)
	}
}

func TestFixCargoLocked(t *testing.T) {
	got := fixPKGBUILD(t, `
build() {
  cargo build --release
}`, FixSafe, nil)
	mustContain(t, got, "cargo build --release --locked")
}

func TestFixGoEnvWeakening(t *testing.T) {
	t.Run("standalone assignment removed", func(t *testing.T) {
		got := fixAll(t, map[string]string{"PKGBUILD": `pkgname=demo
pkgver=1
pkgrel=1
arch=('x86_64')
GOSUMDB=off
source=("https://example.com/demo.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
`}, FixSafe, nil)["PKGBUILD"]
		mustNotContain(t, got, "GOSUMDB")
	})
	t.Run("inline command prefix removed, command kept", func(t *testing.T) {
		got := fixPKGBUILD(t, `
build() {
  GOFLAGS=-insecure go build -o demo .
}`, FixSafe, nil)
		mustNotContain(t, got, "-insecure")
		mustContain(t, got, "go build -o demo .")
	})
}

func TestFixVCSPins(t *testing.T) {
	body := `pkgname=demo
pkgver=1
pkgrel=1
arch=('x86_64')
url='https://example.com'
source=("git+https://example.com/demo.git#tag=v1")
sha256sums=('SKIP')
`
	t.Run("resolves tag to commit", func(t *testing.T) {
		got := fixAll(t, map[string]string{"PKGBUILD": body}, FixSafe, &FixEnv{ResolveRef: fakeResolve})["PKGBUILD"]
		mustContain(t, got, "#commit=0123456789abcdef0123456789abcdef01234567")
		mustNotContain(t, got, "#tag=v1")
	})
	t.Run("offline leaves the ref alone", func(t *testing.T) {
		got := fixAll(t, map[string]string{"PKGBUILD": body}, FixSafe, nil)
		if _, ok := got["PKGBUILD"]; ok {
			t.Errorf("expected no edit without ResolveRef, got:\n%s", got["PKGBUILD"])
		}
	})
	t.Run("signed tag is not rewritten", func(t *testing.T) {
		signed := strings.Replace(body,
			`source=("git+https://example.com/demo.git#tag=v1")`,
			`source=("git+https://example.com/demo.git?signed#tag=v1")`, 1)
		got := fixAll(t, map[string]string{"PKGBUILD": signed}, FixSafe, &FixEnv{ResolveRef: fakeResolve})
		if _, ok := got["PKGBUILD"]; ok {
			t.Errorf("signed tag should not be rewritten, got:\n%s", got["PKGBUILD"])
		}
	})
}

func TestFixGoDownloads(t *testing.T) {
	got := fixPKGBUILD(t, `
build() {
  go build -o demo .
}`, FixUnsafe, nil)
	mustContain(t, got, "go build -mod=vendor -o demo .")
}

func TestFixNpmCI(t *testing.T) {
	got := fixPKGBUILD(t, `
build() {
  npm install
  yarn install
}`, FixUnsafe, nil)
	mustContain(t, got, "npm ci")
	mustContain(t, got, "yarn install --immutable")
}

func TestFixSetuid(t *testing.T) {
	got := fixPKGBUILD(t, `
package() {
  chmod 4755 "$pkgdir/usr/bin/demo"
}`, FixUnsafe, nil)
	mustContain(t, got, "chmod 0755")
	mustNotContain(t, got, "chmod 4755")
}

func TestFixSetuidInstallMode(t *testing.T) {
	got := fixPKGBUILD(t, `
package() {
  install -Dm4755 demo "$pkgdir/usr/bin/demo"
}`, FixUnsafe, nil)
	mustContain(t, got, "install -Dm0755")
	mustNotContain(t, got, "4755")
}

func TestFixBackupSlash(t *testing.T) {
	got := fixAll(t, map[string]string{"PKGBUILD": `pkgname=demo
pkgver=1
pkgrel=1
arch=('x86_64')
backup=('/etc/foo.conf' 'etc/bar.conf')
`}, FixSafe, nil)["PKGBUILD"]
	mustContain(t, got, "'etc/foo.conf'")
	mustContain(t, got, "'etc/bar.conf'")
	mustNotContain(t, got, "'/etc/foo.conf'")
}

func TestFixVariableType(t *testing.T) {
	t.Run("bare word wrapped in array", func(t *testing.T) {
		got := fixAll(t, map[string]string{"PKGBUILD": `pkgname=demo
pkgver=1
pkgrel=1
arch=('x86_64')
depends=gtk3
`}, FixSafe, nil)["PKGBUILD"]
		mustContain(t, got, "depends=(gtk3)")
	})
	t.Run("quoted scalar wrapped preserving the single element", func(t *testing.T) {
		got := fixAll(t, map[string]string{"PKGBUILD": `pkgname=demo
pkgver=1
pkgrel=1
arch=('x86_64')
license="MIT"
`}, FixSafe, nil)["PKGBUILD"]
		mustContain(t, got, `license=("MIT")`)
	})
	t.Run("dynamic scalar is left alone (wrapping would change word splitting)", func(t *testing.T) {
		got := fixAll(t, map[string]string{"PKGBUILD": `pkgname=demo
pkgver=1
pkgrel=1
arch=('x86_64')
depends=$_deps
`}, FixSafe, nil)
		if _, ok := got["PKGBUILD"]; ok {
			t.Errorf("dynamic scalar should not be wrapped, got:\n%s", got["PKGBUILD"])
		}
	})
}

// Unsafe fixes must not run under the safe level.
func TestFixLevelGating(t *testing.T) {
	body := `
build() {
  go build -o demo .
}`
	if got := fixAll(t, map[string]string{"PKGBUILD": pkgbuildWith("", body)}, FixSafe, nil); len(got) != 0 {
		t.Errorf("FixSafe should not apply the unsafe PB204 fix, got:\n%s", got["PKGBUILD"])
	}
	if got := fixPKGBUILD(t, body, FixUnsafe, nil); !strings.Contains(got, "-mod=vendor") {
		t.Errorf("FixUnsafe should apply PB204, got:\n%s", got)
	}
}

// An inline suppression on the finding's line must also suppress its fix.
func TestFixSuppression(t *testing.T) {
	got := fixAll(t, map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  # pkglint: ignore=PB203
  cargo build --release
}`)}, FixSafe, nil)
	if _, ok := got["PKGBUILD"]; ok {
		t.Errorf("suppressed rule should not be fixed, got:\n%s", got["PKGBUILD"])
	}
}

// Applying every fix twice must be a no-op the second time.
func TestFixIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PKGBUILD")
	src := pkgbuildWith("", `
build() {
  cargo build --release
  go build -o demo .
  npm install
}
package() {
  chmod 4755 "$pkgdir/usr/bin/demo"
}`)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	apply := func() bool {
		pkg, err := pkgbuild.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		results := Fix(pkg, nil, FixUnsafe, nil)
		changed := false
		for _, r := range results {
			if r.Changed() {
				changed = true
				if err := os.WriteFile(r.Path, r.Fixed, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		return changed
	}
	if !apply() {
		t.Fatal("first pass made no changes")
	}
	if apply() {
		t.Error("second pass should be a no-op")
	}
}

func TestApplyEdits(t *testing.T) {
	t.Run("non-overlapping edits apply back to front", func(t *testing.T) {
		raw := []byte("abcdefgh")
		out, applied := ApplyEdits(raw, []Edit{
			{Start: 2, End: 4, New: "YY"},
			{Start: 0, End: 1, New: "X"},
		})
		if string(out) != "XbYYefgh" {
			t.Errorf("got %q", out)
		}
		if len(applied) != 2 {
			t.Errorf("expected 2 applied, got %d", len(applied))
		}
	})
	t.Run("insertion", func(t *testing.T) {
		out, _ := ApplyEdits([]byte("ab"), []Edit{{Start: 1, End: 1, New: "-"}})
		if string(out) != "a-b" {
			t.Errorf("got %q", out)
		}
	})
	t.Run("overlapping edits keep the earlier one", func(t *testing.T) {
		out, applied := ApplyEdits([]byte("abcdef"), []Edit{
			{Start: 0, End: 3, New: "X"},
			{Start: 1, End: 2, New: "Y"},
		})
		if string(out) != "Xdef" {
			t.Errorf("got %q", out)
		}
		if len(applied) != 1 {
			t.Errorf("expected 1 applied (overlap dropped), got %d", len(applied))
		}
	})
	t.Run("out-of-range edits are dropped", func(t *testing.T) {
		out, applied := ApplyEdits([]byte("ab"), []Edit{{Start: 5, End: 9, New: "X"}})
		if string(out) != "ab" || len(applied) != 0 {
			t.Errorf("got %q applied=%d", out, len(applied))
		}
	})
}
