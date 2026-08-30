package rules

import (
	"path"
	"strings"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

// PB2xx: hermeticity — network access belongs in the fetch/prepare phase,
// pinned by hashes, so that build()/package()/check() can eventually run
// with networking disabled.
var hermeticRules = []Rule{
	{
		ID:       "PB201",
		Name:     "network-in-build",
		Severity: Warn,
		Doc: "Downloads during build(), check() or package() bypass makepkg's checksum " +
			"verification and make the build non-hermetic: what gets compiled depends on network " +
			"state at build time. Move fetching to prepare() (or better, the source array) where " +
			"artifacts are pinned by lockfiles or checksums.",
		Check: checkNetworkInBuild,
	},
	{
		ID:       "PB202",
		Name:     "pip-without-hashes",
		Severity: Warn,
		Doc: "`pip install` without --require-hashes will happily fetch whatever the index serves. " +
			"With hash-pinned requirements, pip verifies every downloaded artifact against a digest " +
			"recorded in the requirements file.",
		Check: checkPipHashes,
	},
	{
		ID:       "PB203",
		Name:     "cargo-unlocked",
		Severity: Warn,
		Doc: "cargo without --locked (or --frozen/--offline) may resolve and fetch dependency " +
			"versions that differ from the committed Cargo.lock, so the built artifact is not " +
			"reproducible and unreviewed code can enter the build.",
		Check: checkCargoLocked,
		// --locked hard-fails when the source ships no Cargo.lock (or one out
		// of sync with Cargo.toml), so the rewrite can break a working build —
		// the same reason the other lockfile-enforcing fixes (PB206–PB209)
		// are unsafe.
		FixLevel: FixUnsafe,
		Fix:      fixCargoLocked,
	},
	{
		ID:       "PB204",
		Name:     "go-implicit-downloads",
		Severity: Warn,
		Doc: "`go build` fetches modules on demand unless they were vendored or pre-downloaded. " +
			"That download happens inside build() with no makepkg-level verification (go.sum " +
			"verifies content, but resolution still depends on network state). Vendor the modules, " +
			"or run `go mod download` in prepare(). `go install pkg@latest` is worse still: the ref " +
			"is mutable, so what gets built depends on whatever upstream published most recently.",
		Check:    checkGoDownloads,
		FixLevel: FixUnsafe,
		Fix:      fixGoDownloads,
	},
	{
		ID:       "PB205",
		Name:     "go-verification-disabled",
		Severity: Warn,
		Doc: "GOFLAGS/GONOSUMCHECK/GOSUMDB/GOINSECURE settings that disable Go's module checksum " +
			"database or allow insecure transports remove the only integrity verification Go " +
			"downloads get inside a build.",
		Check:    checkGoEnvWeakening,
		FixLevel: FixSafe,
		Fix:      fixGoEnvWeakening,
	},
	{
		ID:       "PB206",
		Name:     "npm-install-unlocked",
		Severity: Info,
		Doc: "`npm install` may rewrite the dependency tree; `npm ci` (and yarn --immutable, " +
			"pnpm/bun --frozen-lockfile) installs exactly what the committed lockfile specifies " +
			"and fails otherwise.",
		Check:    checkNpmCI,
		FixLevel: FixUnsafe,
		Fix:      fixNpmCI,
	},
	{
		ID:       "PB207",
		Name:     "composer-unlocked",
		Severity: Warn,
		Doc: "`composer update` re-resolves and fetches dependency versions, abandoning the " +
			"committed composer.lock — use `composer install`, which installs exactly what the lock " +
			"pins. And either way, composer runs hook scripts and plugins from composer.json and the " +
			"dependency tree during install; pass --no-scripts so fetching packages does not also " +
			"mean executing them, then run any needed build step explicitly.",
		Check:    checkComposer,
		FixLevel: FixUnsafe,
		Fix:      fixComposer,
	},
	{
		ID:       "PB208",
		Name:     "bundler-unlocked",
		Severity: Info, MaxSeverity: Warn, // warn once a fetch is unpinned rather than merely unfrozen
		Doc: "`bundle install` without --frozen (or deployment mode) silently rewrites Gemfile.lock " +
			"when it drifts from the Gemfile, fetching versions nobody reviewed; --frozen makes the " +
			"committed lock authoritative and fails otherwise. Plain `gem install` has no lockfile " +
			"at all — it installs whatever RubyGems serves at build time.",
		Check:    checkBundler,
		FixLevel: FixUnsafe,
		Fix:      fixBundler,
	},
	{
		ID:       "PB209",
		Name:     "uv-poetry-unlocked",
		Severity: Warn,
		Doc: "uv and poetry re-resolve dependencies unless told the committed lockfile is " +
			"authoritative: `uv sync`/`uv run` without --frozen or --locked may rewrite uv.lock, and " +
			"`poetry update`/`poetry add` abandon poetry.lock outright. Pass --frozen, and prefer " +
			"`poetry install` against the committed lock.",
		Check:    checkUvPoetry,
		FixLevel: FixUnsafe,
		Fix:      fixUvFrozen,
	},
}

// networkCommands maps command names to a function deciding whether the
// specific invocation touches the network.
var networkCommands = map[string]func(Command) bool{
	"curl": always, "wget": always, "aria2c": always, "axel": always,
	"scp": always, "sftp": always, "rsync": always,
	"git": func(c Command) bool {
		switch c.Subcommand() {
		case "clone", "fetch", "pull", "ls-remote", "submodule", "remote":
			return true
		}
		return false
	},
	"svn": func(c Command) bool {
		sub := c.Subcommand()
		return sub == "checkout" || sub == "co" || sub == "update" || sub == "export"
	},
	"hg": func(c Command) bool {
		sub := c.Subcommand()
		return sub == "clone" || sub == "pull"
	},
	"go": func(c Command) bool {
		sub := c.Subcommand()
		if sub == "get" || (sub == "mod" && c.HasArg("download")) {
			return true
		}
		if sub == "install" {
			for _, a := range c.Args {
				if strings.Contains(a, "@") {
					return true
				}
			}
		}
		return false
	},
	"pip": pipFetches, "pip3": pipFetches,
	"npm": func(c Command) bool {
		switch c.Subcommand() {
		case "install", "i", "ci", "update", "add":
			return true
		}
		return false
	},
	"pnpm": func(c Command) bool { sub := c.Subcommand(); return sub == "install" || sub == "add" || sub == "i" },
	"yarn": func(c Command) bool { sub := c.Subcommand(); return sub == "install" || sub == "add" || sub == "" },
	"bun":  func(c Command) bool { sub := c.Subcommand(); return sub == "install" || sub == "add" || sub == "i" },
	"cargo": func(c Command) bool {
		return c.Subcommand() == "fetch" && !c.HasArg("--offline")
	},
	"composer": func(c Command) bool { sub := c.Subcommand(); return sub == "install" || sub == "update" },
	"gem":      gemInstallFetches,
	"bundle": func(c Command) bool {
		sub := c.Subcommand()
		return sub == "" || sub == "install" || sub == "update" // bare `bundle` runs install
	},
	"uv": func(c Command) bool {
		switch c.Subcommand() {
		case "sync", "add", "lock", "run":
			return true
		case "pip":
			return uvPipFetches(c)
		case "tool":
			return c.HasArg("install") || c.HasArg("run")
		}
		return false
	},
	"poetry": func(c Command) bool {
		switch c.Subcommand() {
		case "install", "update", "add", "lock":
			return true
		}
		return false
	},
	"dotnet": func(c Command) bool { return c.Subcommand() == "restore" },
	"nuget":  func(c Command) bool { return c.Subcommand() == "restore" },
}

func always(Command) bool { return true }

func pipFetches(c Command) bool {
	sub := c.Subcommand()
	if sub != "install" && sub != "download" {
		return false
	}
	if c.HasArg("--no-index") {
		return false
	}
	// `pip install .` / local paths and wheels don't hit the index when
	// combined with --no-deps, a common packaging idiom.
	if c.HasArg("--no-deps") {
		remote := false
		for _, a := range c.Args {
			if a == sub || hasPrefixAny(a, "-", ".", "/", "$") || strings.HasSuffix(a, ".whl") {
				continue
			}
			remote = true
		}
		return remote
	}
	return true
}

// uvPipFetches mirrors pipFetches for `uv pip install/download`.
func uvPipFetches(c Command) bool {
	if c.Subcommand() != "pip" || (!c.HasArg("install") && !c.HasArg("download")) {
		return false
	}
	if c.HasArg("--no-index") {
		return false
	}
	if c.HasArg("--no-deps") {
		remote := false
		for _, a := range c.Args {
			if a == "pip" || a == "install" || a == "download" ||
				hasPrefixAny(a, "-", ".", "/", "$") || strings.HasSuffix(a, ".whl") {
				continue
			}
			remote = true
		}
		return remote
	}
	return true
}

// gemInstallFetches reports whether a gem install hits RubyGems rather than
// installing local .gem files.
func gemInstallFetches(c Command) bool {
	if c.Subcommand() != "install" || c.HasArg("--local") || c.HasArg("-l") {
		return false
	}
	remote := false
	for _, a := range c.Args {
		if a == "install" || hasPrefixAny(a, "-", ".", "/", "$") || strings.HasSuffix(a, ".gem") {
			continue
		}
		remote = true
	}
	return remote
}

func checkNetworkInBuild(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if !c.InBuildPhase() {
			continue
		}
		if c.Name == "go" { // handled with more context by PB204
			continue
		}
		fetches, ok := networkCommands[c.Name]
		if !ok || !fetches(c) {
			continue
		}
		out = append(out, c.finding("PB201", Warn,
			"%s downloads during %s(); network access belongs in prepare() with pinned hashes", c.Name, c.Fn))
	}
	return out
}

func checkPipHashes(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("pip", "pip3") {
		if c.Subcommand() != "install" || !pipFetches(c) {
			continue
		}
		if c.HasArg("--require-hashes") {
			continue
		}
		out = append(out, c.finding("PB202", Warn,
			"pip install without --require-hashes: downloads are not verified against pinned digests"))
	}
	for _, c := range ctx.CommandsNamed("uv") {
		if !c.HasArg("install") || !uvPipFetches(c) || c.HasArg("--require-hashes") {
			continue
		}
		out = append(out, c.finding("PB202", Warn,
			"uv pip install without --require-hashes: downloads are not verified against pinned digests"))
	}
	return out
}

func checkCargoLocked(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("cargo") {
		switch c.Subcommand() {
		case "build", "install", "fetch", "test", "rustc":
		default:
			continue
		}
		if c.HasArg("--locked") || c.HasArg("--frozen") || c.HasArg("--offline") {
			continue
		}
		out = append(out, c.finding("PB203", Warn,
			"cargo %s without --locked: dependency resolution may diverge from Cargo.lock", c.Subcommand()))
	}
	return out
}

// goVendored reports whether the PKGBUILD vendors Go modules or pre-fetches
// them in prepare(), making implicit build-phase downloads unnecessary.
func goVendored(ctx *Context) bool {
	for _, c := range ctx.CommandsNamed("go") {
		if c.HasArg("-mod=vendor") || (c.Subcommand() == "mod" && (c.HasArg("vendor") || c.HasArg("download")) && !c.InBuildPhase()) {
			return true
		}
	}
	for _, v := range ctx.Pkg.Vars {
		for _, val := range v.Values {
			if strings.Contains(val, "-mod=vendor") {
				return true
			}
		}
	}
	for _, e := range ctx.Pkg.Sources() {
		if isVendorArchive(e) {
			return true
		}
	}
	return false
}

// isVendorArchive reports whether a source looks like a bundled vendored-deps
// archive (vendor.tar.gz, foo-1.0-vendor.tar.zst, a local "vendor" bundle),
// rather than any URL that merely contains the substring "vendor" (e.g. a
// GitHub org literally named "somevendor"). Only the file-name component is
// considered.
func isVendorArchive(e pkgbuild.SourceEntry) bool {
	name := e.Filename // the `name::url` local name, when present
	if name == "" {
		name = path.Base(e.URL)
	}
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "vendor") ||
		strings.Contains(name, "-vendor.") ||
		strings.Contains(name, "vendor.tar")
}

// mutableGoRef reports whether a go package argument pins to a mutable
// @version suffix (latest, a branch name, ...).
func mutableGoRef(arg string) (string, bool) {
	i := strings.LastIndexByte(arg, '@')
	if i < 0 {
		return "", false
	}
	switch ref := arg[i+1:]; ref {
	case "latest", "upgrade", "patch", "master", "main", "HEAD", "tip":
		return ref, true
	}
	return "", false
}

func checkGoDownloads(ctx *Context) []Finding {
	var out []Finding
	// A mutable @ref is a problem in any phase: even fetched in prepare(),
	// what gets built depends on whatever upstream published most recently.
	mutable := map[*syntax.Stmt]bool{}
	for _, c := range ctx.CommandsNamed("go") {
		sub := c.Subcommand()
		if sub != "install" && sub != "run" && sub != "get" {
			continue
		}
		for _, a := range c.Args {
			if ref, ok := mutableGoRef(a); ok {
				out = append(out, c.finding("PB204", Warn,
					"go %s %s resolves mutable ref @%s over the network; pin an exact version or commit", sub, a, ref))
				mutable[c.Stmt] = true
				break
			}
		}
	}
	if goVendored(ctx) {
		return out
	}
	for _, c := range ctx.CommandsNamed("go") {
		if !c.InBuildPhase() || mutable[c.Stmt] {
			continue
		}
		sub := c.Subcommand()
		if sub != "build" && sub != "install" && sub != "test" && sub != "run" && sub != "get" && !(sub == "mod" && c.HasArg("download")) {
			continue
		}
		out = append(out, c.finding("PB204", Warn,
			"go %s may download modules during %s(); vendor them or `go mod download` in prepare()", sub, c.Fn))
	}
	return out
}

// goEnvWeakens reports whether an environment assignment disables Go's module
// checksum database or permits insecure module transports, with a message
// describing the weakening.
func goEnvWeakens(name, value string) (msg string, bad bool) {
	switch name {
	case "GOSUMDB":
		if strings.TrimSpace(value) == "off" {
			return "GOSUMDB=off disables Go's checksum database", true
		}
	case "GONOSUMCHECK", "GONOSUMDB":
		return name + " disables Go module checksum verification", true
	case "GOINSECURE":
		return "GOINSECURE allows fetching modules over insecure transports", true
	case "GOFLAGS":
		if strings.Contains(value, "-insecure") {
			return "GOFLAGS contains -insecure", true
		}
	}
	return "", false
}

func checkGoEnvWeakening(ctx *Context) []Finding {
	var out []Finding
	bad := goEnvWeakens
	for name, v := range ctx.Pkg.Vars {
		if len(v.Values) == 1 {
			if msg, isBad := bad(name, v.Values[0]); isBad {
				out = append(out, findingAt("PB205", Warn, ctx.Pkg.PKGBUILD.Path, v.Pos, "%s", msg))
			}
		}
	}
	for _, c := range ctx.Commands() {
		for _, as := range c.Call.Assigns {
			if as.Name == nil {
				continue
			}
			val := ""
			if as.Value != nil {
				val, _ = renderPlain(as.Value)
			}
			if msg, isBad := bad(as.Name.Value, val); isBad {
				out = append(out, c.finding("PB205", Warn, "%s", msg))
			}
		}
	}
	// `export`/`declare`/`local`/`readonly` are DeclClause nodes, never
	// CallExpr, so they never reach ctx.Commands(). Walk function bodies for
	// them. Top-level ones are already handled via ctx.Pkg.Vars above.
	for _, u := range ctx.Pkg.Units() {
		for _, fn := range u.Functions {
			syntax.Walk(fn.Body, func(n syntax.Node) bool {
				decl, ok := n.(*syntax.DeclClause)
				if !ok {
					return true
				}
				for _, as := range decl.Args {
					if as.Name == nil {
						continue
					}
					val := ""
					if as.Value != nil {
						val, _ = renderPlain(as.Value)
					}
					if msg, isBad := bad(as.Name.Value, val); isBad {
						out = append(out, findingAt("PB205", Warn, u.Path, as.Pos(), "%s", msg))
					}
				}
				return true
			})
		}
	}
	return out
}

func checkNpmCI(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("npm") {
		sub := c.Subcommand()
		if sub == "install" || sub == "i" {
			out = append(out, c.finding("PB206", Info,
				"npm %s may rewrite the dependency tree; prefer `npm ci` against the committed lockfile", sub))
		}
	}
	for _, c := range ctx.CommandsNamed("yarn") {
		if sub := c.Subcommand(); sub == "install" || sub == "" {
			if !c.HasArg("--immutable") && !c.HasArg("--frozen-lockfile") {
				out = append(out, c.finding("PB206", Info,
					"yarn install without --immutable/--frozen-lockfile may rewrite the dependency tree"))
			}
		}
	}
	for _, name := range []string{"pnpm", "bun"} {
		for _, c := range ctx.CommandsNamed(name) {
			if sub := c.Subcommand(); sub == "install" || sub == "i" {
				if !c.HasArg("--frozen-lockfile") && !c.HasArg("--offline") {
					out = append(out, c.finding("PB206", Info,
						"%s %s without --frozen-lockfile may rewrite the dependency tree", name, sub))
				}
			}
		}
	}
	return out
}

func checkComposer(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("composer") {
		switch sub := c.Subcommand(); sub {
		case "update", "upgrade":
			out = append(out, c.finding("PB207", Warn,
				"composer %s re-resolves dependencies away from the committed composer.lock; use `composer install`", sub))
		case "install":
			if !c.HasArg("--no-scripts") {
				out = append(out, c.finding("PB207", Warn,
					"composer install without --no-scripts executes hook scripts and plugins from the dependency tree"))
			}
		}
	}
	return out
}

func checkBundler(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("bundle", "bundler") {
		sub := c.Subcommand()
		if sub != "install" && sub != "" { // bare `bundle` runs install
			continue
		}
		if c.HasArg("--frozen") || c.HasArg("--deployment") || c.HasArg("--local") {
			continue
		}
		out = append(out, c.finding("PB208", Info,
			"bundle install without --frozen may rewrite Gemfile.lock and fetch unreviewed versions"))
	}
	for _, c := range ctx.CommandsNamed("gem") {
		if !gemInstallFetches(c) {
			continue
		}
		out = append(out, c.finding("PB208", Warn,
			"gem install fetches from RubyGems with no lockfile or checksum pinning; install local .gem files (--local) or use bundler against a committed Gemfile.lock"))
	}
	return out
}

func checkUvPoetry(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("uv") {
		sub := c.Subcommand()
		if sub != "sync" && sub != "run" {
			continue
		}
		if c.HasArg("--frozen") || c.HasArg("--locked") || c.HasArg("--offline") || c.HasArg("--no-sync") {
			continue
		}
		out = append(out, c.finding("PB209", Warn,
			"uv %s without --frozen/--locked may re-resolve dependencies and rewrite uv.lock", sub))
	}
	for _, c := range ctx.CommandsNamed("poetry") {
		sub := c.Subcommand()
		if sub != "update" && sub != "add" {
			continue
		}
		out = append(out, c.finding("PB209", Warn,
			"poetry %s re-resolves dependencies away from the committed poetry.lock; use `poetry install`", sub))
	}
	return out
}
