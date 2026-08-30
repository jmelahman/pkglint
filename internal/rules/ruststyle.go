package rules

import "strings"

// PB940–PB942, PB944 lint the Arch Rust package guidelines
// (https://wiki.archlinux.org/title/Rust_package_guidelines): release builds,
// debug-assertion-preserving tests, --no-track installs, and the toolchain
// declared in makedepends. Lockfile enforcement (--locked/--frozen, including
// on `cargo fetch` in prepare()) is hermeticity and already PB203's.

// --- PB940: cargo test/check --release ---------------------------------------

// cargoReleaseFlag returns the spelling the command uses to ask cargo for the
// release profile — `--release` or its short form `-r`, which cargo documents
// as the same flag and which real PKGBUILDs prefer — or "" when it asks for
// neither. Everything after the `--` separator goes to the program cargo runs,
// where `--release` is that program's own argument and none of cargo's
// business.
func cargoReleaseFlag(c Command) string {
	for _, a := range c.Args {
		switch a {
		case "--":
			return ""
		case "--release", "-r":
			return a
		}
	}
	return ""
}

// cargoRelease reports whether the command passes --release to cargo itself.
func cargoRelease(c Command) bool { return cargoReleaseFlag(c) != "" }

func checkCargoCheckRelease(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("cargo") {
		sub := c.Subcommand()
		if (sub != "test" && sub != "check") || !cargoRelease(c) {
			continue
		}
		out = append(out, c.finding("PB940", Warn,
			"cargo %s --release disables debug assertions and overflow checks, weakening exactly what the tests are there to catch; the Rust package guidelines run tests without it", sub))
	}
	return out
}

// --- PB941: cargo install leaves tracking metadata ---------------------------

func checkCargoInstallTracked(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("cargo") {
		if c.Subcommand() != "install" || c.HasArg("--no-track") {
			continue
		}
		out = append(out, c.finding("PB941", Warn,
			"cargo install without --no-track writes .crates.toml/.crates2.json into the install root, which ends up in the package"))
	}
	return out
}

// --- PB942: cargo build without --release ------------------------------------

// cargoDevProfileBuilds returns the build() cargo builds left on cargo's
// unoptimized default profile: the commands PB942 reports, and the ones its
// fix inserts --release into, so rule and fix cannot drift apart.
//
// Two builds are somebody's decision rather than an oversight. One that names
// a profile explicitly (--profile) has chosen it, like an explicit -buildmode
// in PB914. And one whose build() also runs a release build is half of a
// deliberate pair — packages compile the dev profile alongside it for a test
// that needs its stricter limits — where the binary that ships still comes out
// of the release half.
func cargoDevProfileBuilds(ctx *Context) []Command {
	var dev []Command
	release := map[string]bool{}
	for _, c := range ctx.CommandsNamed("cargo") {
		if c.Subcommand() != "build" || c.Fn != "build" {
			continue
		}
		if cargoRelease(c) || cargoHasProfile(c) {
			release[c.Unit.Path] = true
			continue
		}
		dev = append(dev, c)
	}
	out := dev[:0]
	for _, c := range dev {
		if !release[c.Unit.Path] {
			out = append(out, c)
		}
	}
	return out
}

func checkCargoBuildRelease(ctx *Context) []Finding {
	var out []Finding
	for _, c := range cargoDevProfileBuilds(ctx) {
		out = append(out, c.finding("PB942", Info,
			"cargo build without --release ships an unoptimized debug binary; the Rust package guidelines build with --release"))
	}
	return out
}

func cargoHasProfile(c Command) bool {
	for _, a := range c.Args {
		if a == "--profile" || strings.HasPrefix(a, "--profile=") {
			return true
		}
	}
	return false
}

// --- PB944: rust toolchain missing from makedepends --------------------------

// rustToolchainPackages are the packages that put cargo on $PATH.
var rustToolchainPackages = []string{"rust", "rustup"}

func checkRustMakedepends(ctx *Context) []Finding {
	for _, name := range rustToolchainPackages {
		if hasDep(ctx, "makedepends", name) || hasDep(ctx, "depends", name) {
			return nil
		}
	}
	for _, c := range ctx.CommandsNamed("cargo") {
		if c.Unit.Scriptlet || c.Fn == "" {
			continue
		}
		// One finding per PKGBUILD: the remedy is one makedepends entry.
		return []Finding{c.finding("PB944", Info,
			"cargo is used but neither rust nor rustup is in makedepends; a clean build environment cannot run this build")}
	}
	return nil
}
