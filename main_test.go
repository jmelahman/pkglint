package main

import (
	"bytes"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmelahman/pkglint/internal/pkgfile/pkgtest"
	"github.com/jmelahman/pkglint/internal/rules"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestGolden runs the CLI over each package fixture under testdata/ and
// compares the text output against its expected.txt. Line numbers and rule
// hits pin down regressions in parsing and rules alike.
func TestGolden(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			dir := filepath.Join("testdata", e.Name())
			var buf bytes.Buffer
			run([]string{"--fail-on=never", dir}, &buf)
			// Trim the testdata path prefix so the golden file is stable.
			got := strings.ReplaceAll(buf.String(), dir+string(filepath.Separator), "")
			golden := filepath.Join(dir, "expected.txt")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("missing golden file (run with -update): %v", err)
			}
			if got != string(want) {
				t.Errorf("output mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

// TestColorFlag covers the CLI wiring: always forces SGR codes into a
// non-terminal writer, the auto default keeps them out of one (which is what
// keeps the golden files stable), and an unknown mode is a usage error.
func TestColorFlag(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"--fail-on=never", "--color=always", "testdata/malicious"}, &buf); code != 0 {
		t.Fatalf("--color=always: got exit %d, want 0\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("--color=always output has no escape codes:\n%q", buf.String())
	}

	buf.Reset()
	run([]string{"--fail-on=never", "testdata/malicious"}, &buf)
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("default auto mode colored a non-terminal writer:\n%q", buf.String())
	}

	buf.Reset()
	if code := run([]string{"--color=banana", "testdata/clean"}, &buf); code != 2 {
		t.Errorf("--color=banana: got exit %d, want 2", code)
	}
}

func TestColorEnabled(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm")

	if on, err := colorEnabled("always", &bytes.Buffer{}); err != nil || !on {
		t.Errorf("always = (%v, %v), want (true, nil)", on, err)
	}
	if on, err := colorEnabled("never", &bytes.Buffer{}); err != nil || on {
		t.Errorf("never = (%v, %v), want (false, nil)", on, err)
	}
	if _, err := colorEnabled("banana", &bytes.Buffer{}); err == nil {
		t.Error("unknown mode should error")
	}

	// auto: a non-file writer and a regular file are both non-terminals.
	if on, _ := colorEnabled("auto", &bytes.Buffer{}); on {
		t.Error("auto colored a non-file writer")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if on, _ := colorEnabled("auto", f); on {
		t.Error("auto colored a regular file")
	}

	// NO_COLOR and TERM=dumb suppress auto (checked before any tty probe,
	// so the writer's type doesn't matter here).
	t.Setenv("NO_COLOR", "1")
	if on, _ := colorEnabled("auto", os.Stdout); on {
		t.Error("auto ignored NO_COLOR")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if on, _ := colorEnabled("auto", os.Stdout); on {
		t.Error("auto ignored TERM=dumb")
	}
	// An explicit always overrides NO_COLOR (the convention allows it).
	t.Setenv("NO_COLOR", "1")
	if on, _ := colorEnabled("always", os.Stdout); !on {
		t.Error("always should override NO_COLOR")
	}
}

func TestExitCodes(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"--fail-on=critical", "testdata/malicious"}, &buf); code != 1 {
		t.Errorf("malicious fixture at fail-on=critical: got exit %d, want 1", code)
	}
	buf.Reset()
	if code := run([]string{"--fail-on=never", "testdata/malicious"}, &buf); code != 0 {
		t.Errorf("fail-on=never: got exit %d, want 0", code)
	}
	buf.Reset()
	if code := run([]string{"testdata/clean"}, &buf); code != 0 {
		t.Errorf("clean fixture: got exit %d, want 0", code)
	}
	// The default threshold is warn: a package with warn-level findings (and
	// nothing worse) fails without any --fail-on flag.
	buf.Reset()
	if code := run([]string{"testdata/suppressed"}, &buf); code != 1 {
		t.Errorf("warn findings at the default threshold: got exit %d, want 1", code)
	}
}

// TestPackageArchive runs the CLI end-to-end over a synthetic built package:
// a world-writable file is a deterministic, database-independent error.
func TestPackageArchive(t *testing.T) {
	archive := pkgtest.Tar(pkgtest.Info("demo", "any"),
		pkgtest.Member{Name: "usr/bin/demo", Data: []byte("#!/bin/sh\necho demo\n"), Mode: 0o777})
	path := filepath.Join(t.TempDir(), "demo-1.0-1-any.pkg.tar")
	if err := os.WriteFile(path, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if code := run([]string{path}, &buf); code != 1 {
		t.Errorf("package with a world-writable file: got exit %d, want 1\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "PB821") || !strings.Contains(out, "world-writable") {
		t.Errorf("expected a PB821 world-writable finding, got:\n%s", out)
	}
	if !strings.Contains(out, "grade") {
		t.Errorf("expected a letter grade in the report, got:\n%s", out)
	}
	// Fix mode declines package archives instead of erroring.
	buf.Reset()
	if code := run([]string{"--fix", path}, &buf); code != 0 {
		t.Errorf("--fix on an archive: got exit %d, want 0\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "rebuild") {
		t.Errorf("--fix on an archive should explain itself, got:\n%s", buf.String())
	}
}

// fixablePKGBUILD carries one safe line-removal fix (GOSUMDB=off), two unsafe
// fixes (cargo without --locked, npm install), and a SKIP checksum that only
// a manual `updpkgsums` can resolve.
const fixablePKGBUILD = `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
source=("https://example.com/demo-$pkgver.tar.gz")
sha256sums=('SKIP')
export GOSUMDB=off

build() {
  cargo build --release
  npm install
}
`

// writeFixture writes a PKGBUILD into a fresh temp dir with the given mode.
func writeFixture(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFixDiffIsDryRun(t *testing.T) {
	dir := writeFixture(t, fixablePKGBUILD, 0o644)
	var buf bytes.Buffer
	if code := run([]string{"--unsafe-fix", "--diff", dir}, &buf); code != 0 {
		t.Fatalf("--unsafe-fix --diff: got exit %d, want 0\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "dry run") {
		t.Errorf("--diff output should say dry run, got:\n%s", out)
	}
	if !strings.Contains(out, "- ") || !strings.Contains(out, "+   cargo build --release --locked") {
		t.Errorf("--diff output should show before/after hunks, got:\n%s", out)
	}
	got, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != fixablePKGBUILD {
		t.Error("--diff must not modify the file")
	}
}

func TestFixWritesInPlace(t *testing.T) {
	// 0600 pins that writeFixed preserves the file's own permissions
	// instead of resetting them to a default.
	dir := writeFixture(t, fixablePKGBUILD, 0o600)
	var buf bytes.Buffer
	if code := run([]string{"--fix", dir}, &buf); code != 0 {
		t.Fatalf("--fix: got exit %d, want 0\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "applied 1 fix(es)") {
		t.Errorf("want 1 applied fix (GOSUMDB removal), got:\n%s", out)
	}
	if !strings.Contains(out, "updpkgsums") {
		t.Errorf("SKIP checksum should nudge toward updpkgsums, got:\n%s", out)
	}
	fixed, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fixed), "GOSUMDB") {
		t.Errorf("GOSUMDB=off line not removed:\n%s", fixed)
	}
	if strings.Contains(string(fixed), "--locked") {
		t.Errorf("--fix must not apply the unsafe cargo --locked rewrite:\n%s", fixed)
	}
	if strings.Contains(string(fixed), "npm ci") {
		t.Errorf("--fix must not apply the unsafe npm-ci rewrite:\n%s", fixed)
	}
	fi, err := os.Stat(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("writeFixed changed permissions to %o, want 600 preserved", fi.Mode().Perm())
	}
}

func TestUnsafeFixEscalates(t *testing.T) {
	dir := writeFixture(t, fixablePKGBUILD, 0o644)
	var buf bytes.Buffer
	if code := run([]string{"--unsafe-fix", "--offline", dir}, &buf); code != 0 {
		t.Fatalf("--unsafe-fix: got exit %d, want 0\n%s", code, buf.String())
	}
	fixed, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fixed), "npm ci") {
		t.Errorf("--unsafe-fix should rewrite npm install to npm ci:\n%s", fixed)
	}
	if !strings.Contains(string(fixed), "cargo build --release --locked") {
		t.Errorf("--unsafe-fix should append --locked to cargo build:\n%s", fixed)
	}
}

func TestFixNothingToDo(t *testing.T) {
	dir := writeFixture(t, `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
source=("https://example.com/demo-$pkgver.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
`, 0o644)
	var buf bytes.Buffer
	if code := run([]string{"--fix", dir}, &buf); code != 0 {
		t.Fatalf("--fix on clean package: got exit %d, want 0\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "no auto-fixable findings") {
		t.Errorf("want a no-op message, got:\n%s", buf.String())
	}
	var errBuf bytes.Buffer
	if code := run([]string{"--fix", filepath.Join(dir, "does-not-exist")}, &errBuf); code != 2 {
		t.Errorf("--fix on a missing path: got exit %d, want 2", code)
	}
}

// fakeGit puts a stub `git` first on PATH that records every invocation (and
// the GIT_TERMINAL_PROMPT it was handed) in a sentinel file, then prints a
// plausible ls-remote line. It returns a func reporting the recorded
// invocations, so a test can assert git was never reached — and so no test
// here performs real network I/O.
func fakeGit(t *testing.T) func() []string {
	t.Helper()
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "invocations")
	script := "#!/bin/sh\n" +
		`echo "prompt=$GIT_TERMINAL_PROMPT $*" >> "$PKGLINT_TEST_GIT_SENTINEL"` + "\n" +
		`printf '%s\trefs/tags/v1\n' 0123456789abcdef0123456789abcdef01234567` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PKGLINT_TEST_GIT_SENTINEL", sentinel)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		data, err := os.ReadFile(sentinel)
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

// TestResolveGitRefSchemeGuard pins the transport allow-list on the one place
// pkglint shells out with a URL taken from an untrusted PKGBUILD. The rejected
// URLs must never reach git: ext:: and file:// let git run a local command or
// read the local filesystem, and a leading dash is an option, not a remote.
func TestResolveGitRefSchemeGuard(t *testing.T) {
	for _, url := range []string{
		"ext::sh -c whoami",
		"file:///tmp",
		"git+file:///tmp",
		"-oProxyCommand=id",
		"--upload-pack=id",
		"/tmp/local-repo",
		"git@github.com:example/demo.git",
		"ftp://example.com/demo.git",
		"",
	} {
		t.Run("reject "+url, func(t *testing.T) {
			invocations := fakeGit(t)
			if _, err := resolveGitRef(url, "v1"); err == nil || !strings.Contains(err.Error(), "unsupported URL scheme") {
				t.Errorf("resolveGitRef(%q) error = %v, want an unsupported-scheme rejection", url, err)
			}
			if got := invocations(); len(got) != 0 {
				t.Errorf("resolveGitRef(%q) invoked git %v, want no invocation", url, got)
			}
		})
	}

	// The allowed transports must still resolve, and must hand git
	// GIT_TERMINAL_PROMPT=0 so a private remote errors out instead of
	// blocking the fix path on a credential prompt.
	for _, url := range []string{
		"git+https://example.com/demo.git",
		"git+http://example.com/demo.git",
		"git+ssh://git@example.com/demo.git",
		"git://example.com/demo.git",
		"https://example.com/demo.git",
	} {
		t.Run("allow "+url, func(t *testing.T) {
			invocations := fakeGit(t)
			sha, err := resolveGitRef(url, "v1")
			if err != nil {
				t.Fatalf("resolveGitRef(%q) = %v, want success", url, err)
			}
			if sha != "0123456789abcdef0123456789abcdef01234567" {
				t.Errorf("resolveGitRef(%q) sha = %q", url, sha)
			}
			got := invocations()
			if len(got) != 1 {
				t.Fatalf("resolveGitRef(%q) invoked git %d times, want 1: %v", url, len(got), got)
			}
			if !strings.HasPrefix(got[0], "prompt=0 ") {
				t.Errorf("git invoked as %q, want GIT_TERMINAL_PROMPT=0", got[0])
			}
			if strings.Contains(got[0], "git+") {
				t.Errorf("git invoked as %q, want the git+ prefix stripped", got[0])
			}
		})
	}
}

// TestLocalDigestFilenameGuard is localDigest's counterpart to the scheme
// guard above. The name it is handed comes from a source=() entry — the part
// before `::` is written by whoever wrote the PKGBUILD — so anything that is
// not a bare filename must be refused before it is joined to a directory.
// Without this, `../../.ssh/id_ed25519::https://…` would have the fixer hash a
// file outside the package and write the digest into the PKGBUILD.
func TestLocalDigestFilenameGuard(t *testing.T) {
	dir := t.TempDir()
	// A file the traversal attempts would reach if the guard let them through.
	outside := filepath.Dir(dir)
	if err := os.WriteFile(filepath.Join(outside, "victim"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"../victim",
		"../../etc/passwd",
		"sub/demo.tar.gz",
		"/etc/passwd",
		".",
		"..",
		"",
	} {
		t.Run("reject "+name, func(t *testing.T) {
			if _, err := localDigest(dir, name); err == nil ||
				!strings.Contains(err.Error(), "non-filename source") {
				t.Errorf("localDigest(%q) error = %v, want a non-filename rejection", name, err)
			}
		})
	}
}

// A source that is simply not downloaded yet is an ordinary miss, not an
// error the user should see as a rejection: the fixer treats it as "no digest
// available" and leaves the finding standing.
func TestLocalDigestReportsMissingSource(t *testing.T) {
	if _, err := localDigest(t.TempDir(), "demo-1.0.0.tar.gz"); err == nil ||
		!strings.Contains(err.Error(), "not downloaded") {
		t.Errorf("localDigest of an absent source = %v, want a not-downloaded error", err)
	}
}

// The digests must be those of the file actually on disk, and must all come
// from one read — that agreement is the whole basis for trusting the sha256
// the PB102 fix writes.
func TestLocalDigestHashesTheFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "demo.tar.gz"), []byte("hello pkglint\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := localDigest(dir, "demo.tar.gz")
	if err != nil {
		t.Fatalf("localDigest: %v", err)
	}
	// Independently produced: printf 'hello pkglint\n' | md5sum / sha1sum / sha256sum
	want := rules.Digests{
		MD5:    "81e9507e65bc63dd82650f6e96666192",
		SHA1:   "c5be7bc75da5a8cacf181fe5a8a3cc9f7ac33dfb",
		SHA256: "ba77dc247b5b85c4a0f955c19011f57614e7135998f1c4d875348381f38d9695",
	}
	if got != want {
		t.Errorf("localDigest = %+v, want %+v", got, want)
	}
}

// $SRCDEST is where makepkg parks shared downloads, so a source cached there
// counts as fetched even though it is not beside the PKGBUILD.
func TestLocalDigestFindsSrcdest(t *testing.T) {
	cache := t.TempDir()
	if err := os.WriteFile(filepath.Join(cache, "demo.tar.gz"), []byte("hello pkglint\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SRCDEST", cache)
	got, err := localDigest(t.TempDir(), "demo.tar.gz")
	if err != nil {
		t.Fatalf("localDigest: %v", err)
	}
	if got.SHA256 != "ba77dc247b5b85c4a0f955c19011f57614e7135998f1c4d875348381f38d9695" {
		t.Errorf("SHA256 = %q, want the cached file's digest", got.SHA256)
	}
}

// The full PB102 path through --fix: a downloaded source whose weak digest
// matches gains a sha256sums array, and the updpkgsums nudge — computed from
// what is left *after* fixing — goes quiet, because the finding it nudged
// about is now closed.
func TestFixWeakChecksumsEndToEnd(t *testing.T) {
	dir := writeFixture(t, `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
source=("https://example.com/demo-$pkgver.tar.gz")
md5sums=('81e9507e65bc63dd82650f6e96666192')
`, 0o644)
	if err := os.WriteFile(filepath.Join(dir, "demo-1.0.0.tar.gz"), []byte("hello pkglint\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if code := run([]string{"--fix", dir}, &buf); code != 0 {
		t.Fatalf("--fix: got exit %d, want 0\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "[PB102]") {
		t.Errorf("expected a PB102 fix to be reported, got:\n%s", out)
	}
	if strings.Contains(out, "updpkgsums") {
		t.Errorf("the checksum fix was applied, so the updpkgsums nudge should be gone:\n%s", out)
	}
	got, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "sha256sums=('ba77dc247b5b85c4a0f955c19011f57614e7135998f1c4d875348381f38d9695')") {
		t.Errorf("PKGBUILD should carry the local file's sha256, got:\n%s", got)
	}
}

// The post-fix reload that recomputes the nudges re-reads the file's inline
// directives; under --no-inline-ignores they must stay disregarded, or a
// suppressed finding's nudge would vanish exactly when some other fix applied.
func TestFixNoInlineKeepsNudges(t *testing.T) {
	dir := writeFixture(t, `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
source=("https://example.com/demo-$pkgver.tar.gz")
md5sums=('81e9507e65bc63dd82650f6e96666192') # pkglint: ignore=PB102
export GOSUMDB=off
`, 0o644)
	var buf bytes.Buffer
	if code := run([]string{"--fix", "--no-inline-ignores", dir}, &buf); code != 0 {
		t.Fatalf("--fix --no-inline-ignores: got exit %d, want 0\n%s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "[PB205]") {
		t.Errorf("expected the GOSUMDB fix to apply, got:\n%s", out)
	}
	if !strings.Contains(out, "updpkgsums") {
		t.Errorf("--no-inline-ignores surfaces the suppressed PB102, so its nudge must survive the post-fix reload:\n%s", out)
	}
}

// TestNoInlineIgnores pins the audit mode: without the flag the maintainer's
// directives are honored (and audited by PB913); with it they are disregarded
// entirely, so the suppressed findings surface and nothing audits comments
// that are no longer in force.
func TestNoInlineIgnores(t *testing.T) {
	var buf bytes.Buffer
	run([]string{"--fail-on=never", "testdata/suppressed"}, &buf)
	trusted := buf.String()
	if !strings.Contains(trusted, "PB913") {
		t.Errorf("default run should flag the stale directive, got:\n%s", trusted)
	}
	if strings.Contains(trusted, "PB204") {
		t.Errorf("default run should honor the PB204 suppression, got:\n%s", trusted)
	}

	buf.Reset()
	run([]string{"--fail-on=never", "--no-inline-ignores", "testdata/suppressed"}, &buf)
	audited := buf.String()
	if !strings.Contains(audited, "PB204") {
		t.Errorf("--no-inline-ignores should surface the suppressed PB204, got:\n%s", audited)
	}
	if strings.Contains(audited, "PB913") {
		t.Errorf("--no-inline-ignores disables directives, so none can be stale, got:\n%s", audited)
	}
}

// --add-ignores rewrites the package to accept its current findings; mixing it
// with modes that fix or distrust the same annotations is contradictory.
func TestAddIgnoresRejectsConflictingFlags(t *testing.T) {
	for _, flags := range [][]string{
		{"--add-ignores", "--fix"},
		{"--add-ignores", "--unsafe-fix"},
		{"--add-ignores", "--no-inline-ignores"},
	} {
		var buf bytes.Buffer
		if code := run(append(flags, "testdata/clean"), &buf); code != 2 {
			t.Errorf("%v: got exit %d, want 2", flags, code)
		}
	}
}

func TestAddIgnoresWritesAndDryRuns(t *testing.T) {
	const body = `pkgname=demo
pkgver=1.0.0
pkgrel=1
pkgdesc='demo'
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
source=("https://example.com/demo-$pkgver.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
makedepends=('rust')

build() {
  cargo build --release
}
`
	dir := writeFixture(t, "# Maintainer: Sam Coder <sam@example.com>\n"+body, 0o644)

	var buf bytes.Buffer
	if code := run([]string{"--add-ignores", "--diff", dir}, &buf); code != 0 {
		t.Fatalf("--add-ignores --diff: got exit %d, want 0\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "dry run") || !strings.Contains(buf.String(), "+   # pkglint: ignore=PB203") {
		t.Errorf("dry run should preview the insertion, got:\n%s", buf.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "ignore=") {
		t.Error("--diff must not modify the file")
	}

	buf.Reset()
	if code := run([]string{"--add-ignores", dir}, &buf); code != 0 {
		t.Fatalf("--add-ignores: got exit %d, want 0\n%s", code, buf.String())
	}
	fixed, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fixed), "# pkglint: ignore=PB203\n  cargo build --release") {
		t.Errorf("directive not inserted above the finding:\n%s", fixed)
	}

	// The annotated package now lints clean at the default threshold.
	buf.Reset()
	if code := run([]string{dir}, &buf); code != 0 {
		t.Errorf("annotated package should lint clean, exit %d:\n%s", code, buf.String())
	}
}

// TestProbeHTTPS covers the check that stands between PB104's finding and its
// rewrite. The fix is only as good as this probe: a false "reachable" writes a
// URL nobody has confirmed, and a false "unreachable" costs nothing but the
// fix, which is the direction to err in.
func TestProbeHTTPS(t *testing.T) {
	// A TLS test server plus its own trusted client, with the production
	// redirect policy layered back on. The dial guard below rejects loopback,
	// so the transport is the one part swapped out here — and it is exercised
	// on its own in TestProbeHTTPSRefusesInternalAddresses.
	newServer := func(t *testing.T, h http.HandlerFunc) (string, *http.Client) {
		t.Helper()
		srv := httptest.NewTLSServer(h)
		t.Cleanup(srv.Close)
		client := newProbeClient()
		client.Transport = srv.Client().Transport
		return srv.URL, client
	}

	t.Run("a served URL passes", func(t *testing.T) {
		url, client := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodHead {
				t.Errorf("method = %s, want HEAD", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		})
		if err := probeWith(client, url+"/demo.tar.gz"); err != nil {
			t.Errorf("probe = %v, want success", err)
		}
	})

	// The common real failure: the host speaks https but does not have this
	// path, which is exactly the build the unverified rewrite would have broken.
	t.Run("a 404 fails", func(t *testing.T) {
		url, client := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		err := probeWith(client, url+"/demo.tar.gz")
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Errorf("probe = %v, want a 404 refusal", err)
		}
	})

	// Plenty of servers reject HEAD while serving the file happily. That is a
	// statement about the method, not the URL, so the probe asks again for a
	// single byte rather than reporting the source unreachable.
	for name, status := range map[string]int{
		"405": http.StatusMethodNotAllowed,
		"403": http.StatusForbidden,
		"501": http.StatusNotImplemented,
	} {
		t.Run("HEAD "+name+" falls back to a ranged GET", func(t *testing.T) {
			var gets int
			url, client := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(status)
					return
				}
				gets++
				if r.Header.Get("Range") != "bytes=0-0" {
					t.Errorf("Range = %q, want a single byte", r.Header.Get("Range"))
				}
				w.WriteHeader(http.StatusPartialContent)
			})
			if err := probeWith(client, url+"/demo.tar.gz"); err != nil {
				t.Errorf("probe = %v, want success via the GET fallback", err)
			}
			if gets != 1 {
				t.Errorf("issued %d GETs, want 1", gets)
			}
		})
	}

	// A redirect landing on http means the https URL does not actually serve
	// the file — the opposite of what the fix would be claiming.
	t.Run("a redirect off https fails", func(t *testing.T) {
		url, client := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, "http://example.com/demo.tar.gz", http.StatusFound)
		})
		err := probeWith(client, url+"/demo.tar.gz")
		if err == nil || !strings.Contains(err.Error(), "redirected off https") {
			t.Errorf("probe = %v, want a downgrade refusal", err)
		}
	})

	t.Run("a non-https URL is refused outright", func(t *testing.T) {
		for _, u := range []string{"http://example.com/x", "ftp://example.com/x", "://nonsense"} {
			if err := probeWith(newProbeClient(), u); err == nil {
				t.Errorf("probe(%q) = nil, want a refusal", u)
			}
		}
	})
}

// TestProbeHTTPSRefusesInternalAddresses pins the guard that keeps a probe on
// the public internet. The URL being probed comes out of a file pkglint is
// analyzing *because* nobody has vetted it, so a PKGBUILD naming the cloud
// metadata service or a host resolving to one must not turn linting into a
// request to it.
func TestProbeHTTPSRefusesInternalAddresses(t *testing.T) {
	for _, u := range []string{
		"https://127.0.0.1/latest/meta-data/",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.1/internal.tar.gz",
		"https://192.168.1.1/internal.tar.gz",
		"https://[::1]/internal.tar.gz",
	} {
		t.Run(u, func(t *testing.T) {
			err := probeHTTPS(u)
			if err == nil || !strings.Contains(err.Error(), "non-public address") {
				t.Errorf("probeHTTPS(%q) = %v, want a non-public-address refusal", u, err)
			}
		})
	}
}

func TestRefuseInternalAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"93.184.216.34:443":  true, // public
		"[2606:2800::1]:443": true,
		"127.0.0.1:443":      false,
		"[::1]:443":          false,
		"10.1.2.3:443":       false,
		"172.16.0.1:443":     false,
		"192.168.0.5:443":    false,
		"169.254.169.254:80": false,
		"0.0.0.0:443":        false,
		"224.0.0.1:443":      false,
		"[fd00::1]:443":      false, // unique-local
		"not-an-address":     false,
	} {
		err := refuseInternalAddr("tcp", addr, nil)
		if got := err == nil; got != want {
			t.Errorf("refuseInternalAddr(%q) allowed = %v (err %v), want %v", addr, got, err, want)
		}
	}
}
