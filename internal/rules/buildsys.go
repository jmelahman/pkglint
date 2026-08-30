package rules

import "strings"

// PB950–PB955 lint the Arch CMake and Meson package guidelines
// (https://wiki.archlinux.org/title/CMake_package_guidelines,
// https://wiki.archlinux.org/title/Meson_package_guidelines): the /usr
// prefix, CMake's flag-clobbering Release build type, the build tools
// declared in makedepends, and meson's compile wrapper instead of bare
// ninja. Redirecting the install step into $pkgdir is PB404's.

// --- shared cmake/meson argument helpers -------------------------------------

// cmakeConfigures reports whether a cmake invocation is a configure step —
// the one that fixes the install prefix and build type — rather than one of
// cmake's other modes (--build, --install, script/tool execution).
func cmakeConfigures(c Command) bool {
	for _, a := range c.Args {
		switch a {
		case "--build", "--install", "--open", "--find-package", "--workflow",
			"-E", "-P", "--version", "--help":
			return false
		}
	}
	return true
}

// cmakeDefine returns the value of a -Dname=value cache define, handling the
// split "-D name=value" spelling and cmake's typed "-Dname:TYPE=value" form.
func cmakeDefine(c Command, name string) (string, bool) {
	tail := func(a, prefix string) (string, bool) {
		rest, ok := strings.CutPrefix(a, prefix)
		if !ok {
			return "", false
		}
		if i := strings.IndexByte(rest, '='); i >= 0 && (i == 0 || rest[0] == ':') {
			return rest[i+1:], true
		}
		return "", false
	}
	for i, a := range c.Args {
		if v, ok := tail(a, "-D"+name); ok {
			return v, true
		}
		if a == "-D" && i+1 < len(c.Args) {
			if v, ok := tail(c.Args[i+1], name); ok {
				return v, true
			}
		}
	}
	return "", false
}

// hasArraySplat reports whether any argument word expands a whole array
// ("${_cmake_args[@]}") — the long-invocation idiom whose flags static
// reading cannot see, so absence claims about them would be guesses.
func hasArraySplat(c Command) bool {
	raw := c.Unit.Raw
	for _, w := range c.Call.Args {
		start, end := int(w.Pos().Offset()), int(w.End().Offset())
		if start < 0 || end > len(raw) || start >= end {
			continue
		}
		if strings.Contains(string(raw[start:end]), "[@]") || strings.Contains(string(raw[start:end]), "[*]") {
			return true
		}
	}
	return false
}

// mesonNonSetupSubcommands are the meson verbs that are not a project
// configure; anything else — `meson setup`, or the legacy `meson builddir`
// spelling where the first word is a directory — configures the build.
var mesonNonSetupSubcommands = map[string]bool{
	"compile": true, "test": true, "install": true, "dist": true,
	"configure": true, "introspect": true, "init": true, "wrap": true,
	"subprojects": true, "rewrite": true, "devenv": true, "format": true,
}

func mesonConfigures(c Command) bool {
	return !mesonNonSetupSubcommands[c.Subcommand()]
}

func mesonSetsPrefix(c Command) bool {
	for _, a := range c.Args {
		if a == "--prefix" || strings.HasPrefix(a, "--prefix=") || strings.HasPrefix(a, "-Dprefix=") {
			return true
		}
	}
	return false
}

// buildToolCommands returns the non-scriptlet, in-function invocations of the
// named tools.
func buildToolCommands(ctx *Context, names ...string) []Command {
	var out []Command
	for _, c := range ctx.CommandsNamed(names...) {
		if c.Unit.Scriptlet || c.Fn == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// checkToolMakedepends is the shared shape of PB944/PB952/PB954: the build
// invokes tool but no listed package puts it on $PATH.
func checkToolMakedepends(ctx *Context, id string, cmds []Command, tool string, packages ...string) []Finding {
	if len(cmds) == 0 {
		return nil
	}
	for _, name := range packages {
		if hasDep(ctx, "makedepends", name) || hasDep(ctx, "depends", name) {
			return nil
		}
	}
	// One finding per PKGBUILD: the remedy is one makedepends entry.
	return []Finding{cmds[0].finding(id, Warn,
		"%s is used but %q is not in makedepends; a clean build environment cannot run this build", tool, packages[0])}
}

// --- PB950: cmake configure without an install prefix ------------------------

func checkCMakePrefix(ctx *Context) []Finding {
	var configures []Command
	for _, c := range buildToolCommands(ctx, "cmake") {
		if !cmakeConfigures(c) {
			continue
		}
		// Any explicit prefix is a decision (the guidelines allow /opt for
		// self-contained trees) — and one that covers the whole PKGBUILD: a
		// second configure without it builds bundled deps or a test tree that
		// installs nothing (neovim's cmake.deps), not the shipped artifacts.
		// A splatted flag array may carry the prefix invisibly, so it stands
		// the whole rule down too.
		if _, ok := cmakeDefine(c, "CMAKE_INSTALL_PREFIX"); ok || hasArraySplat(c) {
			return nil
		}
		configures = append(configures, c)
	}
	var out []Finding
	for _, c := range configures {
		out = append(out, c.finding("PB950", Warn,
			"cmake configure without -DCMAKE_INSTALL_PREFIX=/usr defaults to /usr/local, which Arch packages must not touch"))
	}
	return out
}

// --- PB951: CMAKE_BUILD_TYPE=Release clobbers Arch's flags -------------------

func checkCMakeBuildType(ctx *Context) []Finding {
	var out []Finding
	for _, c := range buildToolCommands(ctx, "cmake") {
		if !cmakeConfigures(c) {
			continue
		}
		if v, ok := cmakeDefine(c, "CMAKE_BUILD_TYPE"); ok && v == "Release" {
			out = append(out, c.finding("PB951", Warn,
				"-DCMAKE_BUILD_TYPE=Release appends -O3 -DNDEBUG after Arch's CFLAGS, overriding the distribution's -O2; the CMake package guidelines build with -DCMAKE_BUILD_TYPE=None"))
		}
	}
	return out
}

// --- PB952/PB954: build system missing from makedepends ----------------------

// depNameContains reports whether any depends/makedepends entry's name
// contains sub — the leniency the cross-toolchain wrappers need, where
// mingw-w64-cmake (which pulls cmake) is the declared dependency.
func depNameContains(ctx *Context, sub string) bool {
	for _, field := range []string{"depends", "makedepends"} {
		for name := range depsFor(ctx, field) {
			if strings.Contains(name, sub) {
				return true
			}
		}
	}
	return false
}

func checkCMakeMakedepends(ctx *Context) []Finding {
	if depNameContains(ctx, "cmake") {
		return nil
	}
	return checkToolMakedepends(ctx, "PB952", buildToolCommands(ctx, "cmake"), "cmake", "cmake")
}

func checkMesonMakedepends(ctx *Context) []Finding {
	if depNameContains(ctx, "meson") {
		return nil
	}
	return checkToolMakedepends(ctx, "PB954",
		buildToolCommands(ctx, "meson", "arch-meson"), "meson", "meson")
}

// --- PB953: meson setup without --prefix -------------------------------------

func checkMesonPrefix(ctx *Context) []Finding {
	var out []Finding
	for _, c := range buildToolCommands(ctx, "meson") {
		if !mesonConfigures(c) || mesonSetsPrefix(c) || hasArraySplat(c) {
			continue
		}
		out = append(out, c.finding("PB953", Warn,
			"meson setup without --prefix=/usr defaults to /usr/local, which Arch packages must not touch (arch-meson passes the guideline flags for you)"))
	}
	return out
}

// --- PB955: bare ninja in a meson build --------------------------------------

func checkMesonNinjaDirect(ctx *Context) []Finding {
	if len(buildToolCommands(ctx, "meson", "arch-meson")) == 0 {
		return nil
	}
	var out []Finding
	for _, c := range buildToolCommands(ctx, "ninja") {
		out = append(out, c.finding("PB955", Info,
			"this project is configured with meson; `meson compile` (and `meson install`, `meson test`) wraps ninja with the configured environment — prefer it over calling ninja directly"))
	}
	return out
}
