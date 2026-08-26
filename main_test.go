package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
