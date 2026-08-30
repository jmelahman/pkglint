package rules

import "strings"

// PB940–PB942, PB944 lint the Arch Rust package guidelines
// (https://wiki.archlinux.org/title/Rust_package_guidelines): release builds,
// debug-assertion-preserving tests, --no-track installs, and the toolchain
// declared in makedepends. Lockfile enforcement (--locked/--frozen, including
// on `cargo fetch` in prepare()) is hermeticity and already PB203's.

// --- PB940: cargo test/check --release ---------------------------------------

func checkCargoCheckRelease(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("cargo") {
		sub := c.Subcommand()
		if (sub != "test" && sub != "check") || !c.HasArg("--release") {
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

func checkCargoBuildRelease(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("cargo") {
		if c.Subcommand() != "build" || c.Fn != "build" || c.HasArg("--release") {
			continue
		}
		// An explicit profile is a decision, like an explicit -buildmode in
		// PB914.
		if cargoHasProfile(c) {
			continue
		}
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
