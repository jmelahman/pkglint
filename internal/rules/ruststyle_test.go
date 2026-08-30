package rules

import "testing"

func TestRustGuidelineRules(t *testing.T) {
	t.Run("PB940 cargo test --release", func(t *testing.T) {
		expectRule(t, "PB940", map[string]string{"PKGBUILD": pkgbuildWith("", `
check() {
  cargo test --release --locked
}`)})
	})
	t.Run("PB940 cargo check --release", func(t *testing.T) {
		expectRule(t, "PB940", map[string]string{"PKGBUILD": pkgbuildWith("", `
check() {
  cargo check --release --locked
}`)})
	})
	t.Run("PB940 debug-profile tests are the guideline", func(t *testing.T) {
		expectNoRule(t, "PB940", map[string]string{"PKGBUILD": pkgbuildWith("", `
check() {
  cargo test --locked
}`)})
	})
	t.Run("PB940 -r is the same flag", func(t *testing.T) {
		expectRule(t, "PB940", map[string]string{"PKGBUILD": pkgbuildWith("", `
check() {
  cargo test -r --locked
}`)})
	})
	t.Run("PB940 release build in build() is not a test", func(t *testing.T) {
		expectNoRule(t, "PB940", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build --release --locked
}`)})
	})

	t.Run("PB941 cargo install without --no-track", func(t *testing.T) {
		expectRule(t, "PB941", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  cargo install --locked --root "$pkgdir/usr" --path .
}`)})
	})
	t.Run("PB941 --no-track is the fix", func(t *testing.T) {
		expectNoRule(t, "PB941", map[string]string{"PKGBUILD": pkgbuildWith("", `
package() {
  cargo install --locked --no-track --root "$pkgdir/usr" --path .
}`)})
	})

	t.Run("PB942 cargo build without --release", func(t *testing.T) {
		expectRule(t, "PB942", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build --locked
}`)})
	})
	t.Run("PB942 --release is the guideline", func(t *testing.T) {
		expectNoRule(t, "PB942", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build --release --locked
}`)})
	})
	t.Run("PB942 -r asks for the same profile", func(t *testing.T) {
		expectNoRule(t, "PB942", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build -r --locked
}`)})
	})
	t.Run("PB942 an explicit profile is a decision", func(t *testing.T) {
		expectNoRule(t, "PB942", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build --profile dist --locked
}`)})
	})
	t.Run("PB942 a release build alongside it is the shipped one", func(t *testing.T) {
		// Both profiles on purpose: the dev binary is what the test suite
		// needs, and the release one is what the package installs.
		expectNoRule(t, "PB942", map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build --locked
  cargo build --locked --release
}`)})
	})
	t.Run("PB942 cargo build outside build() is not the shipped artifact", func(t *testing.T) {
		expectNoRule(t, "PB942", map[string]string{"PKGBUILD": pkgbuildWith("", `
prepare() {
  cargo build --locked
}`)})
	})

	t.Run("PB944 cargo without rust in makedepends", func(t *testing.T) {
		files := map[string]string{"PKGBUILD": pkgbuildWith("", `
build() {
  cargo build --release --locked
}
check() {
  cargo test --locked
}`)}
		if n := ruleIDs(lint(t, files))["PB944"]; n != 1 {
			t.Errorf("PB944 fired %d times, want exactly 1", n)
		}
	})
	t.Run("PB944 rust in makedepends satisfies it", func(t *testing.T) {
		expectNoRule(t, "PB944", map[string]string{"PKGBUILD": pkgbuildWith("", `
makedepends=('rust')
build() {
  cargo build --release --locked
}`)})
	})
	t.Run("PB944 rustup counts too", func(t *testing.T) {
		expectNoRule(t, "PB944", map[string]string{"PKGBUILD": pkgbuildWith("", `
makedepends=('rustup')
build() {
  cargo build --release --locked
}`)})
	})
	t.Run("PB944 rust in depends counts", func(t *testing.T) {
		expectNoRule(t, "PB944", map[string]string{"PKGBUILD": pkgbuildWith("", `
depends=('rust')
build() {
  cargo build --release --locked
}`)})
	})
}
