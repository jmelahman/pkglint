package rules

import "strings"

// PB2xx: hermeticity — network access belongs in the fetch/prepare phase,
// pinned by hashes, so that build()/package()/check() can eventually run
// with networking disabled.
var hermeticRules = []Rule{
	{
		ID:   "PB201",
		Name: "network-in-build",
		Doc: "Downloads during build(), check() or package() bypass makepkg's checksum " +
			"verification and make the build non-hermetic: what gets compiled depends on network " +
			"state at build time. Move fetching to prepare() (or better, the source array) where " +
			"artifacts are pinned by lockfiles or checksums.",
		Check: checkNetworkInBuild,
	},
	{
		ID:   "PB202",
		Name: "pip-without-hashes",
		Doc: "`pip install` without --require-hashes will happily fetch whatever the index serves. " +
			"With hash-pinned requirements, pip verifies every downloaded artifact against a digest " +
			"recorded in the requirements file.",
		Check: checkPipHashes,
	},
	{
		ID:   "PB203",
		Name: "cargo-unlocked",
		Doc: "cargo without --locked (or --frozen/--offline) may resolve and fetch dependency " +
			"versions that differ from the committed Cargo.lock, so the built artifact is not " +
			"reproducible and unreviewed code can enter the build.",
		Check:    checkCargoLocked,
		FixLevel: FixSafe,
		Fix:      fixCargoLocked,
	},
	{
		ID:   "PB204",
		Name: "go-implicit-downloads",
		Doc: "`go build` fetches modules on demand unless they were vendored or pre-downloaded. " +
			"That download happens inside build() with no makepkg-level verification (go.sum " +
			"verifies content, but resolution still depends on network state). Vendor the modules, " +
			"or run `go mod download` in prepare().",
		Check:    checkGoDownloads,
		FixLevel: FixUnsafe,
		Fix:      fixGoDownloads,
	},
	{
		ID:   "PB205",
		Name: "go-verification-disabled",
		Doc: "GOFLAGS/GONOSUMCHECK/GOSUMDB/GOINSECURE settings that disable Go's module checksum " +
			"database or allow insecure transports remove the only integrity verification Go " +
			"downloads get inside a build.",
		Check:    checkGoEnvWeakening,
		FixLevel: FixSafe,
		Fix:      fixGoEnvWeakening,
	},
	{
		ID:   "PB206",
		Name: "npm-install-unlocked",
		Doc: "`npm install` may rewrite the dependency tree; `npm ci` (and yarn --immutable) " +
			"installs exactly what the committed lockfile specifies and fails otherwise.",
		Check:    checkNpmCI,
		FixLevel: FixUnsafe,
		Fix:      fixNpmCI,
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
	"gem":      func(c Command) bool { return c.Subcommand() == "install" },
	"dotnet":   func(c Command) bool { return c.Subcommand() == "restore" },
	"nuget":    func(c Command) bool { return c.Subcommand() == "restore" },
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
		if strings.Contains(strings.ToLower(e.Expanded), "vendor") {
			return true
		}
	}
	return false
}

func checkGoDownloads(ctx *Context) []Finding {
	if goVendored(ctx) {
		return nil
	}
	var out []Finding
	for _, c := range ctx.CommandsNamed("go") {
		if !c.InBuildPhase() {
			continue
		}
		sub := c.Subcommand()
		if sub != "build" && sub != "install" && sub != "test" && sub != "run" && !(sub == "mod" && c.HasArg("download")) {
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
		if c.Name == "export" || c.Name == "declare" {
			for _, a := range c.Args {
				if name, val, ok := strings.Cut(a, "="); ok {
					if msg, isBad := bad(name, val); isBad {
						out = append(out, c.finding("PB205", Warn, "%s", msg))
					}
				}
			}
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
	return out
}
