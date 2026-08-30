package rules

import "testing"

// vcsHeaderWith builds a -git PKGBUILD head around the given source array
// element and extra metadata lines.
func vcsHeaderWith(name, source, extra string) string {
	return `pkgname=` + name + `
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
makedepends=('git')
` + extra + `source=(` + source + `)
sha256sums=('SKIP')`
}

const demoPkgverFn = `
pkgver() {
  cd demo
  git describe --long --tags
}`

func TestVCSGuidelineRules(t *testing.T) {
	t.Run("PB960 tip-following source without pkgver()", func(t *testing.T) {
		expectRule(t, "PB960", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"git+https://example.com/demo.git"`, ""), "")})
	})
	t.Run("PB960 pkgver() is the fix", func(t *testing.T) {
		expectNoRule(t, "PB960", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"git+https://example.com/demo.git"`, ""), demoPkgverFn)})
	})
	t.Run("PB960 pkgver() inside a top-level if still counts", func(t *testing.T) {
		expectNoRule(t, "PB960", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"git+https://example.com/demo.git"`, ""), `
if [[ -n $_release ]]; then
  pkgver() {
    printf '1.0.0'
  }
else
  pkgver() {
    cd demo
    git describe --long --tags
  }
fi`)})
	})
	t.Run("PB960 a commit-pinned source is a snapshot, not a tip", func(t *testing.T) {
		expectNoRule(t, "PB960", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo", `"git+https://example.com/demo.git#commit=3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"`, ""), "")})
	})

	t.Run("PB961 no provides or conflicts on the base name", func(t *testing.T) {
		expectRule(t, "PB961", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"git+https://example.com/demo.git"`, ""), demoPkgverFn)})
	})
	t.Run("PB961 declaring either stands down", func(t *testing.T) {
		expectNoRule(t, "PB961", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"git+https://example.com/demo.git"`,
				"provides=(\"demo=$pkgver\")\nconflicts=('demo')\n"), demoPkgverFn)})
		expectNoRule(t, "PB961", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"git+https://example.com/demo.git"`,
				"provides=('demo')\n"), demoPkgverFn)})
	})
	t.Run("PB961 unsuffixed packages are exempt", func(t *testing.T) {
		expectNoRule(t, "PB961", map[string]string{"PKGBUILD": pkgbuildWith("", "")})
	})

	t.Run("PB962 pkgver in the checkout folder", func(t *testing.T) {
		expectRule(t, "PB962", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"$pkgname-$pkgver::git+https://example.com/demo.git"`, ""), demoPkgverFn)})
	})
	t.Run("PB962 stable folder name is fine", func(t *testing.T) {
		expectNoRule(t, "PB962", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"$pkgname::git+https://example.com/demo.git"`, ""), demoPkgverFn)})
	})
	t.Run("PB962 versioned tarball names are normal", func(t *testing.T) {
		expectNoRule(t, "PB962", map[string]string{"PKGBUILD": pkgbuildWith("", "")})
	})

	t.Run("PB963 -git name with a tarball source", func(t *testing.T) {
		expectRule(t, "PB963", map[string]string{"PKGBUILD": pkgbuildWith(`pkgname=demo-git
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com/demo'
license=('MIT')
source=("https://example.com/demo-1.0.0.tar.gz")
sha256sums=('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`, "")})
	})
	t.Run("PB963 -git name pinned to a fixed commit", func(t *testing.T) {
		expectRule(t, "PB963", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"git+https://example.com/demo.git#commit=3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"`, ""), "")})
	})
	t.Run("PB963 suffix and tip-following source agree", func(t *testing.T) {
		expectNoRule(t, "PB963", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo-git", `"git+https://example.com/demo.git"`, ""), demoPkgverFn)})
	})
	t.Run("PB963 unsuffixed pinned checkout is fine", func(t *testing.T) {
		expectNoRule(t, "PB963", map[string]string{"PKGBUILD": pkgbuildWith(
			vcsHeaderWith("demo", `"git+https://example.com/demo.git#commit=3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"`, ""), "")})
	})
}
