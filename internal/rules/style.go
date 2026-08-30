package rules

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// PB9xx: PKGBUILD style and distro hygiene. These mirror namcap's stylistic
// PKGBUILD checks: nothing here breaks a build or smuggles code, but each is a
// deviation from Arch packaging conventions that makes a package harder to
// maintain, port, or review. Severities are deliberately modest — Warn for
// things a reviewer would ask to change, Info for pure convention.
var styleRules = []Rule{
	{
		ID:       "PB901",
		Name:     "specific-host-arch",
		Severity: Warn,
		Doc: "Hardcoding an architecture name (x86_64, aarch64, …) in sources, flags or paths " +
			"ties the PKGBUILD to one machine type; $CARCH expands to the architecture being built " +
			"for. Assignments to arch=() and to already arch-suffixed fields (source_x86_64=…) are " +
			"exempt — those are the places an explicit architecture belongs.",
		Check: checkSpecificHostArch,
	},
	{
		ID:       "PB902",
		Name:     "unprefixed-custom-variable",
		Severity: Warn,
		Doc: "Custom variables must start with an underscore (_commit, _pyname) so they can never " +
			"collide with a current or future makepkg field. A bare custom name is silently shipped " +
			"to any tool that parses PKGBUILD metadata and may change meaning under a newer pacman.",
		Check: checkUnprefixedCustomVars,
	},
	{
		ID:       "PB903",
		Name:     "startdir-reference",
		Severity: Warn,
		Doc: "$startdir is a makepkg implementation detail from before $srcdir and $pkgdir " +
			"existed. Paths built from it ($startdir/pkg, $startdir/src) break under makepkg's " +
			"BUILDDIR/PKGDEST redirection; use $srcdir and $pkgdir, which are always correct.",
		Check: checkStartdirReference,
	},
	{
		ID:       "PB904",
		Name:     "redundant-makedepends",
		Severity: Warn,
		Doc: "Everything in depends is installed during the build too, so repeating a package in " +
			"makedepends adds nothing and misleads readers about the build's real extra " +
			"requirements. An entry is only kept when its version constraint differs.",
		Check: checkRedundantMakedepends,
	},
	{
		ID:       "PB905",
		Name:     "sourceforge-mirror-url",
		Severity: Info,
		Doc: "SourceForge URLs pinned to a specific mirror (heanet.dl.sourceforge.net, " +
			"dl.sf.net, …) break when that mirror retires. downloads.sourceforge.net picks a " +
			"working mirror automatically and is the form Arch packaging guidelines ask for.",
		Check: checkSourceforgeMirror,
	},
	{
		ID:       "PB906",
		Name:     "pkgname-in-pkgdesc",
		Severity: Info,
		Doc: "pkgdesc is displayed next to the package name everywhere pacman shows it, so " +
			"repeating the name inside the description wastes the one line that should say what " +
			"the software does.",
		Check: checkPkgnameInDesc,
	},
	{
		ID:       "PB907",
		Name:     "makepkg-internal-function",
		Severity: Warn,
		Doc: "msg, msg2, warning, error and plain are makepkg's private output helpers, not an " +
			"API: they vanish when the PKGBUILD is parsed by anything other than makepkg itself " +
			"and their behavior changes between pacman releases. Use echo or printf.",
		Check: checkMakepkgInternalFunctions,
	},
	{
		ID:       "PB908",
		Name:     "missing-maintainer-comment",
		Severity: Info,
		Doc: "AUR convention puts a '# Maintainer: Name <email>' comment at the top of every " +
			"PKGBUILD so users know who to contact and whether the package is orphaned. Namcap " +
			"checks for the same tag.",
		Check: checkMaintainerComment,
	},
	{
		ID:       "PB909",
		Name:     "uppercase-pkgname",
		Severity: Warn,
		Doc: "Arch package names are lowercase by convention, even when upstream's name is not " +
			"(python, not Python). makepkg accepts uppercase, so this only surfaces in repo " +
			"tooling and user confusion later — rename now, keep the case in pkgdesc.",
		Check: checkUppercasePkgname,
	},
	{
		ID:       "PB910",
		Name:     "missing-metadata",
		Severity: Warn,
		Doc: "pkgdesc, url and license are not required by makepkg but are required by Arch " +
			"packaging standards: without them pacman -Qi shows blanks and the package's legal " +
			"status is undeclared. Split packages may set them per package function instead.",
		Check: checkMissingMetadata,
	},
	{
		ID:       "PB911",
		Name:     "non-unique-source-name",
		Severity: Warn,
		Doc: "A source that downloads to a bare version-numbered file (v1.2.3.tar.gz) collides " +
			"with every other package doing the same in a shared SRCDEST cache, silently reusing " +
			"the wrong tarball. Rename it: \"$pkgname-$pkgver.tar.gz::https://…/v1.2.3.tar.gz\".",
		Check: checkNonUniqueSourceName,
	},
	{
		ID:       "PB912",
		Name:     "duplicated-optdepends",
		Severity: Warn,
		Doc: "A package listed in both depends and optdepends is contradictory metadata: the " +
			"hard dependency always wins, and the optdepends line falsely suggests the feature " +
			"is optional. Keep exactly one of the two.",
		Check: checkDuplicatedOptdepends,
	},
	{
		ID:       "PB913",
		Name:     "stale-ignore-directive",
		Severity: Warn,
		Doc: "A '# pkglint: ignore=' directive that matches no finding on its own or the next " +
			"line — the issue was fixed, or the ID was never a pkglint rule — no longer documents " +
			"a reviewed exception. It misleads reviewers into thinking a finding exists there, and " +
			"if the flagged construct ever comes back, the leftover directive silences it without " +
			"anyone re-reviewing. The auto-fix removes the stale IDs, or the whole comment once " +
			"none remain.",
		Check:    checkStaleIgnores,
		FixLevel: FixSafe,
		Fix:      fixStaleIgnores,
	},
	{
		ID:       "PB914",
		Name:     "go-no-pie",
		Severity: Warn,
		Doc: "The Arch Go packaging guidelines build with -buildmode=pie: without it the Go " +
			"toolchain links a position-dependent executable that ASLR cannot relocate, which " +
			"PB806 flags on the built package. Set it in GOFLAGS or on the go build command; a " +
			"PKGBUILD that chooses another -buildmode explicitly is left alone.",
		Check: checkGoPIE,
		// Changing the link layout of the shipped binary is behavior a human
		// should sign off on, like the other build-command rewrites.
		FixLevel: FixUnsafe,
		Fix:      fixGoPIE,
	},
	{
		ID:       "PB915",
		Name:     "go-no-trimpath",
		Severity: Warn,
		Doc: "Without -trimpath, go embeds absolute $srcdir paths in the binary, so two builders " +
			"never produce the same bytes and the package leaks its build layout. The Arch Go " +
			"packaging guidelines put -trimpath in GOFLAGS on every build.",
		Check:    checkGoTrimpath,
		FixLevel: FixUnsafe,
		Fix:      fixGoTrimpath,
	},
	{
		ID:       "PB916",
		Name:     "go-readonly-modcache",
		Severity: Info,
		Doc: "go writes its module cache read-only, so after a build that fetched modules, " +
			"cleaning $srcdir (or $GOPATH under it) fails until someone chmods the tree. The Arch " +
			"Go packaging guidelines pass -modcacherw on every module-aware command to keep the " +
			"cache removable.",
		Check: checkGoModcacheRW,
		// -modcacherw only loosens permissions on cache files; it cannot
		// change what gets built, so the rewrite is safe.
		FixLevel: FixSafe,
		Fix:      fixGoModcacheRW,
	},
	{
		ID:       "PB917",
		Name:     "go-cgo-flags-dropped",
		Severity: Info,
		Doc: "cgo compiles C with CGO_CFLAGS/CGO_LDFLAGS, not the CFLAGS/LDFLAGS makepkg exports, " +
			"so unless the PKGBUILD forwards them (export CGO_CFLAGS=\"$CFLAGS\", …) Arch's " +
			"fortify/RELRO hardening never reaches the C parts of a Go build. Pure-Go packages " +
			"can set CGO_ENABLED=0 instead, which also silences this rule.",
		Check: checkGoCgoFlags,
	},
	{
		ID:       "PB918",
		Name:     "self-provides",
		Severity: Warn,
		Doc: "Every package implicitly provides its own name, so listing $pkgname in provides is " +
			"dead metadata — at best ignored, at worst masking a typo of the capability the entry " +
			"was meant to declare. The Arch package guidelines say provides is for other " +
			"capabilities the package supplies (a library soname, a renamed predecessor).",
		Check: checkSelfProvides,
	},
	{
		ID:       "PB919",
		Name:     "self-conflicts",
		Severity: Warn,
		Doc: "A package can never conflict with itself — pacman resolves same-name conflicts by " +
			"upgrading — so listing $pkgname in conflicts is dead metadata that misleads readers " +
			"about what the package actually displaces. The Arch package guidelines say to drop it.",
		Check: checkSelfConflicts,
	},
	{
		ID:       "PB920",
		Name:     "non-spdx-license",
		Severity: Info,
		Doc: "Arch migrated the license field to SPDX expressions (RFC 16): 'GPL-2.0-or-later' " +
			"says which GPL and whether later versions qualify, where the legacy 'GPL' said " +
			"neither, and license-audit tooling parses only the SPDX form. Only known-legacy " +
			"spellings are flagged, so a valid-but-uncommon SPDX identifier never is.",
		Check: checkNonSPDXLicense,
	},
	{
		ID:       "PB921",
		Name:     "usr-local-install",
		Severity: Warn,
		Doc: "/usr/local is reserved for software the administrator builds outside the package " +
			"manager; the Arch package guidelines forbid packages from touching it. This is the " +
			"PKGBUILD-side complement of PB820, which flags the same files in the built archive. " +
			"Install under /usr (usually /usr/bin, /usr/lib, /usr/share) instead.",
		Check: checkUsrLocalInstall,
	},
	{
		ID:       "PB922",
		Name:     "usr-libexec-install",
		Severity: Info,
		Doc: "Arch does not use /usr/libexec: the package guidelines put internal executables " +
			"that users should not invoke directly in /usr/lib/$pkgname instead. Upstream build " +
			"systems often default libexecdir to /usr/libexec, so the fix is usually " +
			"--libexecdir=/usr/lib on configure rather than moving files by hand.",
		Check: checkUsrLibexecInstall,
	},
	{
		ID:       "PB930",
		Name:     "python-tox",
		Severity: Warn,
		Doc: "tox exists to test against multiple Python versions by building fresh virtualenvs " +
			"and re-resolving dependencies from PyPI — the opposite of checking that *this* " +
			"package works against *this* system's packages, and a network dependency inside " +
			"check(). The Arch Python package guidelines forbid it; invoke pytest (or upstream's " +
			"runner) directly.",
		Check: checkPythonTox,
	},
	{
		ID:       "PB931",
		Name:     "python-lint-checkdepends",
		Severity: Info,
		Doc: "pytest plugins like pytest-cov, pytest-black or pytest-mypy lint upstream's code " +
			"style or measure coverage; neither says anything about whether the built package " +
			"works, and a new linter release starts failing builds that did not change. The Arch " +
			"Python package guidelines say check() runs tests, not upstream's CI.",
		Check: checkPythonLintCheckdepends,
	},
	{
		ID:       "PB932",
		Name:     "python-prebuilt-wheel",
		Severity: Warn,
		Doc: "A .whl source is a pre-built artifact: what lands in the package was compiled by " +
			"whoever uploaded the wheel, not by this PKGBUILD, so nothing reviewed here is what " +
			"ships. The Arch Python package guidelines require building from the source " +
			"distribution except where no sdist exists at all.",
		Check: checkPythonWheelSource,
	},
	{
		ID:       "PB933",
		Name:     "python-missing-build-backend",
		Severity: Warn,
		Doc: "`python -m build` and `python -m installer` come from the python-build and " +
			"python-installer packages, which makepkg does not install for you: without them in " +
			"makedepends the build fails in any clean chroot, however reliably it works on the " +
			"maintainer's machine.",
		Check: checkPythonBuildBackend,
	},
	{
		ID:       "PB934",
		Name:     "python-setup-py",
		Severity: Warn,
		Doc: "`python setup.py install` runs the distutils flow that setuptools has removed: it " +
			"bypasses PEP 517 build isolation, writes egg-info metadata pip cannot manage, and " +
			"breaks outright on modern setuptools. The Arch Python package guidelines build with " +
			"`python -m build` and stage with `python -m installer`.",
		Check: checkPythonSetupPy,
	},
	{
		ID:       "PB940",
		Name:     "cargo-check-release",
		Severity: Warn,
		Doc: "--release on cargo test/check disables debug assertions and integer-overflow " +
			"checks — precisely the invariants a test run exists to exercise. The Arch Rust " +
			"package guidelines run check() without --release; the shipped binary is still built " +
			"--release in build().",
		Check: checkCargoCheckRelease,
	},
	{
		ID:       "PB941",
		Name:     "cargo-install-tracked",
		Severity: Warn,
		Doc: "cargo install records what it installed in .crates.toml and .crates2.json under the " +
			"install root; staged into $pkgdir those files ship in the package, conflict with " +
			"every other Rust package doing the same, and describe a cargo state directory that " +
			"does not exist on the user's system. The Rust package guidelines pass --no-track.",
		Check: checkCargoInstallTracked,
	},
	{
		ID:       "PB942",
		Name:     "cargo-build-not-release",
		Severity: Info,
		Doc: "cargo builds the unoptimized, debug-assertion-laden dev profile unless told " +
			"otherwise, so a plain `cargo build` in build() ships a slow binary. The Arch Rust " +
			"package guidelines build with --release; a PKGBUILD that selects another profile " +
			"explicitly (--profile) has made the call and is left alone.",
		Check: checkCargoBuildRelease,
	},
	{
		ID:       "PB944",
		Name:     "rust-missing-makedepends",
		Severity: Info,
		Doc: "cargo is not part of the base build environment: without rust (or rustup) in " +
			"makedepends the build fails in any clean chroot. rustup satisfies the dependency " +
			"for maintainers who manage toolchains themselves, so either spelling counts.",
		Check: checkRustMakedepends,
	},
}

// --- PB901: hardcoded host architecture ------------------------------------

var hostArchRe = regexp.MustCompile(
	`\b(i386|i486|i586|i686|x86_64|aarch64|armv6h|armv7h|arm|ppc|riscv64|loong64)\b`)

// checkSpecificHostArch mirrors namcap's carch rule on the AST: any literal
// mentioning a concrete architecture is flagged unless it is (part of) an
// arch=() assignment, an assignment to an arch-suffixed field, or on a line
// that also expands $CARCH (the idiom the rule is nudging toward).
func checkSpecificHostArch(ctx *Context) []Finding {
	u := ctx.Pkg.PKGBUILD

	// Lines exempt from the check.
	skip := map[uint]bool{}
	markSpan := func(from, to syntax.Pos) {
		for l := from.Line(); l <= to.Line(); l++ {
			skip[l] = true
		}
	}
	for name, v := range ctx.Pkg.Vars {
		if v.Assign == nil {
			continue
		}
		if strings.HasSuffix(name, "arch") || archSuffixed(name) {
			markSpan(v.Assign.Pos(), v.Assign.End())
		}
	}
	syntax.Walk(u.File, func(node syntax.Node) bool {
		if pe, ok := node.(*syntax.ParamExp); ok && pe.Param != nil && pe.Param.Value == "CARCH" {
			skip[pe.Pos().Line()] = true
		}
		return true
	})

	var out []Finding
	type key struct {
		line uint
		arch string
	}
	seen := map[key]bool{}
	report := func(val string, pos syntax.Pos) {
		m := hostArchRe.FindString(val)
		if m == "" || skip[pos.Line()] {
			return
		}
		if seen[key{pos.Line(), m}] {
			return
		}
		seen[key{pos.Line(), m}] = true
		out = append(out, findingAt("PB901", Warn, u.Path, pos,
			"architecture %q is hardcoded; use $CARCH so the PKGBUILD ports to other architectures", m))
	}
	syntax.Walk(u.File, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.Lit:
			report(x.Value, x.Pos())
		case *syntax.SglQuoted:
			report(x.Value, x.Pos())
		}
		return true
	})
	return out
}

// hostArchNames are the architectures hostArchRe recognizes, for suffix tests.
var hostArchNames = []string{
	"i386", "i486", "i586", "i686", "x86_64", "aarch64", "armv6h", "armv7h", "arm",
	"ppc", "riscv64", "loong64",
}

// archSuffixed reports whether name is a schema field suffixed with an
// architecture (source_x86_64, depends_aarch64, …). The arch names themselves
// contain underscores, so this is a suffix test, not a split on '_'.
func archSuffixed(name string) bool {
	for _, a := range hostArchNames {
		if strings.HasSuffix(name, "_"+a) {
			return true
		}
	}
	return false
}

// --- PB902: custom variables without an underscore prefix -------------------

// knownPKGBUILDVars is every variable name makepkg itself reads, i.e. the ones
// a PKGBUILD may set without an underscore prefix.
func knownPKGBUILDVars(ctx *Context) map[string]bool {
	known := map[string]bool{"pkgname": true, "pkgbase": true}
	for _, n := range schemaArrayVars {
		known[n] = true
	}
	for _, n := range schemaStringVars {
		known[n] = true
	}
	for _, a := range concreteArches(ctx) {
		for _, n := range schemaArchArrayVars {
			known[n+"_"+a] = true
		}
	}
	return known
}

func checkUnprefixedCustomVars(ctx *Context) []Finding {
	known := knownPKGBUILDVars(ctx)
	var out []Finding
	for name, v := range ctx.Pkg.Vars {
		if known[name] || strings.HasPrefix(name, "_") {
			continue
		}
		// All-uppercase and mixed-case names are either makepkg.conf overrides
		// (PB108's concern) or at least visually distinct; namcap only flags
		// all-lowercase names, and so do we.
		if name != strings.ToLower(name) {
			continue
		}
		out = append(out, findingAt("PB902", Warn, ctx.Pkg.PKGBUILD.Path, v.Pos,
			"custom variable %q should be prefixed with an underscore (_%s) to avoid clashing with makepkg fields",
			name, name))
	}
	return out
}

// --- PB903: $startdir --------------------------------------------------------

func checkStartdirReference(ctx *Context) []Finding {
	u := ctx.Pkg.PKGBUILD
	var out []Finding
	syntax.Walk(u.File, func(node syntax.Node) bool {
		pe, ok := node.(*syntax.ParamExp)
		if !ok || pe.Param == nil || pe.Param.Value != "startdir" {
			return true
		}
		// Peek at what follows in the raw text: "$startdir/pkg" and
		// "$startdir/src" have exact replacements, anything else is a generic
		// deprecation. An intervening closing quote ("$startdir"/pkg) is
		// skipped, as namcap does.
		msg := "$startdir is deprecated; use $srcdir and $pkgdir instead"
		tail := u.Raw[min(int(pe.End().Offset()), len(u.Raw)):]
		if len(tail) > 0 && tail[0] == '"' {
			tail = tail[1:]
		}
		switch {
		case hasPrefixAny(string(tail), "/pkg"):
			msg = "use $pkgdir instead of $startdir/pkg"
		case hasPrefixAny(string(tail), "/src"):
			msg = "use $srcdir instead of $startdir/src"
		}
		out = append(out, findingAt("PB903", Warn, u.Path, pe.Pos(), "%s", msg))
		return true
	})
	return out
}

// --- PB904: makedepends already in depends ----------------------------------

// depName strips the version constraint from a dependency entry:
// "foo>=1.2" -> "foo". optdepends-style ": description" suffixes are cut too.
func depName(entry string) string {
	if i := strings.IndexByte(entry, ':'); i >= 0 {
		entry = entry[:i]
	}
	if i := strings.IndexAny(entry, "<>="); i >= 0 {
		entry = entry[:i]
	}
	return strings.TrimSpace(entry)
}

// depsFor collects the statically-known entries of field and its declared
// _$arch variants, mapping name -> full entry as written.
func depsFor(ctx *Context, field string) map[string]string {
	out := map[string]string{}
	names := []string{field}
	for _, a := range concreteArches(ctx) {
		names = append(names, field+"_"+a)
	}
	for _, n := range names {
		for _, e := range varElems(ctx.Pkg.Vars[n]) {
			if val, ok := staticVal(ctx.Pkg, e.Value); ok && val != "" {
				out[depName(val)] = val
			}
		}
	}
	return out
}

func checkRedundantMakedepends(ctx *Context) []Finding {
	depends := depsFor(ctx, "depends")
	if len(depends) == 0 {
		return nil
	}
	var out []Finding
	names := []string{"makedepends"}
	for _, a := range concreteArches(ctx) {
		names = append(names, "makedepends_"+a)
	}
	for _, n := range names {
		for _, e := range varElems(ctx.Pkg.Vars[n]) {
			val, ok := staticVal(ctx.Pkg, e.Value)
			if !ok || val == "" {
				continue
			}
			name := depName(val)
			full, dup := depends[name]
			if !dup {
				continue
			}
			// A makedepends entry with its own, different version constraint
			// is a deliberate build-time requirement; leave it alone.
			if name != val && full != val {
				continue
			}
			out = append(out, findingAt("PB904", Warn, ctx.Pkg.PKGBUILD.Path, e.Pos,
				"%q is already in depends; every runtime dependency is installed at build time too", val))
		}
	}
	return out
}

// --- PB905: pinned SourceForge mirrors ---------------------------------------

func checkSourceforgeMirror(ctx *Context) []Finding {
	var out []Finding
	for _, e := range ctx.Pkg.Sources() {
		host := strings.ToLower(e.Host())
		if host == "" {
			continue
		}
		pinned := host == "dl.sourceforge.net" || host == "dl.sf.net" ||
			strings.HasSuffix(host, ".dl.sourceforge.net") || strings.HasSuffix(host, ".dl.sf.net")
		if !pinned {
			continue
		}
		out = append(out, findingAt("PB905", Info, ctx.Pkg.PKGBUILD.Path, e.Pos,
			"source pins the SourceForge mirror %q; use https://downloads.sourceforge.net so a working mirror is chosen automatically", host))
	}
	return out
}

// --- PB906: package name repeated in pkgdesc ---------------------------------

func checkPkgnameInDesc(ctx *Context) []Finding {
	v := ctx.Pkg.Vars["pkgdesc"]
	if v == nil || v.Array {
		return nil
	}
	desc, ok := staticVal(ctx.Pkg, firstValue(v.Values))
	if !ok || desc == "" {
		return nil
	}
	words := map[string]bool{}
	for _, w := range strings.Fields(strings.ToLower(desc)) {
		words[w] = true
	}
	for _, e := range varElems(ctx.Pkg.Vars["pkgname"]) {
		name, ok := staticVal(ctx.Pkg, e.Value)
		if !ok || name == "" {
			continue
		}
		if words[strings.ToLower(name)] {
			return []Finding{findingAt("PB906", Info, ctx.Pkg.PKGBUILD.Path, v.Pos,
				"pkgdesc repeats the package name %q; describe what the software does instead", name)}
		}
	}
	return nil
}

// --- PB907: makepkg's private output helpers ---------------------------------

var makepkgInternalFns = map[string]bool{
	"msg": true, "msg2": true, "warning": true, "error": true, "plain": true,
}

func checkMakepkgInternalFunctions(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if c.Unit.Scriptlet || c.Fn == "" || !makepkgInternalFns[c.Name] || len(c.Args) == 0 {
			continue
		}
		// A function of the same name defined in the PKGBUILD is the
		// packager's own; only bare calls reach makepkg's helpers.
		if _, defined := c.Unit.Functions[c.Name]; defined {
			continue
		}
		out = append(out, c.finding("PB907", Warn,
			"%s is a makepkg-internal helper, not a stable API; use echo or printf", c.Name))
	}
	return out
}

// --- PB908: maintainer tag ---------------------------------------------------

var maintainerTagRe = regexp.MustCompile(`(?im)^\s*#\s*Maintainer\s*:`)

func checkMaintainerComment(ctx *Context) []Finding {
	if maintainerTagRe.Match(ctx.Pkg.PKGBUILD.Raw) {
		return nil
	}
	return []Finding{{RuleID: "PB908", Severity: Info, Path: ctx.Pkg.PKGBUILD.Path, Line: 1, Col: 1,
		Message: "no '# Maintainer:' comment; AUR convention names the responsible maintainer at the top of the PKGBUILD"}}
}

// --- PB909: uppercase package names ------------------------------------------

func checkUppercasePkgname(ctx *Context) []Finding {
	var out []Finding
	for _, field := range []string{"pkgname", "pkgbase"} {
		for _, e := range varElems(ctx.Pkg.Vars[field]) {
			val, ok := staticVal(ctx.Pkg, e.Value)
			if !ok || val == strings.ToLower(val) {
				continue
			}
			out = append(out, findingAt("PB909", Warn, ctx.Pkg.PKGBUILD.Path, e.Pos,
				"%s %q contains uppercase letters; Arch package names are lowercase by convention", field, val))
		}
	}
	return out
}

// --- PB910: pkgdesc / url / license presence ---------------------------------

func checkMissingMetadata(ctx *Context) []Finding {
	var out []Finding
	for _, field := range []string{"pkgdesc", "url", "license"} {
		if v := ctx.Pkg.Vars[field]; v != nil && len(v.Values) > 0 && firstValue(v.Values) != "" {
			continue
		}
		if fieldSetInPackageFns(ctx, field) {
			continue // split packages may declare it per package function
		}
		if ctx.Pkg.ConditionalVars[field] {
			continue // set by a top-level branch the parser cannot resolve
		}
		out = append(out, Finding{RuleID: "PB910", Severity: Warn, Path: ctx.Pkg.PKGBUILD.Path,
			Line: 1, Col: 1,
			Message: field + " is not set; Arch packaging standards require it on every package"})
	}
	return out
}

// fieldSetInPackageFns reports whether any package_*() function assigns name.
func fieldSetInPackageFns(ctx *Context, name string) bool {
	found := false
	for fn, fd := range ctx.Pkg.PKGBUILD.Functions {
		if fn != "package" && !strings.HasPrefix(fn, "package_") {
			continue
		}
		syntax.Walk(fd, func(node syntax.Node) bool {
			call, ok := node.(*syntax.CallExpr)
			if !ok {
				return true
			}
			for _, as := range call.Assigns {
				if as.Name != nil && as.Name.Value == name {
					found = true
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// --- PB911: version-only download names --------------------------------------

// versionNameRe matches basenames that are nothing but a (possibly v-prefixed)
// version or date followed by an extension: v1.2.3.tar.gz, 20240101.zip.
var versionNameRe = regexp.MustCompile(`^[vV]?(([0-9]){8}|([0-9]+\.?)+)\.`)

func checkNonUniqueSourceName(ctx *Context) []Finding {
	var out []Finding
	for _, e := range ctx.Pkg.Sources() {
		if e.Local || e.VCS != "" || e.Filename != "" || e.URL == "" {
			continue
		}
		base := basename(e.URL)
		if i := strings.IndexAny(base, "#?"); i >= 0 {
			base = base[:i]
		}
		if !versionNameRe.MatchString(base) {
			continue
		}
		out = append(out, findingAt("PB911", Warn, ctx.Pkg.PKGBUILD.Path, e.Pos,
			"source downloads to %q, which does not identify the package; rename it with \"$pkgname-$pkgver.tar.gz::url\"", base))
	}
	return out
}

// --- PB912: depends repeated in optdepends -----------------------------------

func checkDuplicatedOptdepends(ctx *Context) []Finding {
	depends := depsFor(ctx, "depends")
	if len(depends) == 0 {
		return nil
	}
	var out []Finding
	names := []string{"optdepends"}
	for _, a := range concreteArches(ctx) {
		names = append(names, "optdepends_"+a)
	}
	for _, n := range names {
		for _, e := range varElems(ctx.Pkg.Vars[n]) {
			val, ok := staticVal(ctx.Pkg, e.Value)
			if !ok || val == "" {
				continue
			}
			if _, dup := depends[depName(val)]; !dup {
				continue
			}
			out = append(out, findingAt("PB912", Warn, ctx.Pkg.PKGBUILD.Path, e.Pos,
				"%q is optional here but already a hard dependency in depends; keep one of the two", depName(val)))
		}
	}
	return out
}
