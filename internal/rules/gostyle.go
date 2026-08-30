package rules

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// PB914–PB917 lint the build-flag conventions of the Arch Linux Go package
// guidelines (https://wiki.archlinux.org/title/Go_package_guidelines): PIE
// hardening, reproducible paths, a writable module cache, and toolchain flags
// reaching cgo. The guidelines' module-download and verification advice is
// hermeticity and already covered by PB204/PB205; `-mod=readonly` is not
// linted because it has been Go's default since 1.16.

// assignmentsTo returns the rendered value of every assignment to name
// anywhere in the PKGBUILD — top-level, `export`ed inside a function, or a
// command's environment prefix. Dynamic parts render as their literal
// fragments, so `GOFLAGS="$GOFLAGS -trimpath"` still reveals the appended
// flag; values that are entirely dynamic render empty but still count as an
// assignment.
func assignmentsTo(ctx *Context, name string) []string {
	var out []string
	syntax.Walk(ctx.Pkg.PKGBUILD.File, func(node syntax.Node) bool {
		if as, ok := node.(*syntax.Assign); ok && as.Name != nil && as.Name.Value == name && as.Value != nil {
			s, _ := renderPlain(as.Value)
			out = append(out, s)
		}
		return true
	})
	return out
}

// goFlagAddressed reports whether the PKGBUILD says anything about flag for
// this command: as an argument (any "-flag..." spelling, so an explicit
// opt-out counts as a decision) or inside a GOFLAGS assignment.
func goFlagAddressed(goflags []string, c Command, flag string) bool {
	for _, a := range c.Args {
		if strings.HasPrefix(a, flag) {
			return true
		}
	}
	for _, v := range goflags {
		if strings.Contains(v, flag) {
			return true
		}
	}
	return false
}

// goBuildCommands returns the `go build` / `go install` invocations that
// produce the artifacts the package ships (build/check/package functions).
func goBuildCommands(ctx *Context) []Command {
	var out []Command
	for _, c := range ctx.CommandsNamed("go") {
		if !c.InBuildPhase() {
			continue
		}
		switch c.Subcommand() {
		case "build", "install":
			out = append(out, c)
		}
	}
	return out
}

// secondSubcommand returns the verb after a two-word go subcommand ("mod
// download" → "download"), or "".
func secondSubcommand(c Command) string {
	seen := false
	for _, a := range c.Args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if !seen {
			seen = true
			continue
		}
		return a
	}
	return ""
}

// goModuleCommands returns every go invocation that writes the module cache,
// in any function of the PKGBUILD — prepare() is exactly where the guidelines
// put `go mod download`.
func goModuleCommands(ctx *Context) []Command {
	var out []Command
	for _, c := range ctx.CommandsNamed("go") {
		if c.Unit.Scriptlet || c.Fn == "" {
			continue
		}
		switch c.Subcommand() {
		case "build", "install", "test", "run", "get":
			out = append(out, c)
		case "mod":
			switch secondSubcommand(c) {
			case "download", "tidy", "vendor":
				out = append(out, c)
			}
		}
	}
	return out
}

// --- PB914: go build without -buildmode=pie ----------------------------------

func checkGoPIE(ctx *Context) []Finding {
	goflags := assignmentsTo(ctx, "GOFLAGS")
	var out []Finding
	for _, c := range goBuildCommands(ctx) {
		if goFlagAddressed(goflags, c, "-buildmode") {
			continue
		}
		out = append(out, c.finding("PB914", Warn,
			"go %s without -buildmode=pie produces a non-PIE executable, so ASLR cannot relocate it; set it in GOFLAGS or on the command", c.Subcommand()))
	}
	return out
}

// --- PB915: go build without -trimpath ----------------------------------------

func checkGoTrimpath(ctx *Context) []Finding {
	goflags := assignmentsTo(ctx, "GOFLAGS")
	var out []Finding
	for _, c := range goBuildCommands(ctx) {
		if goFlagAddressed(goflags, c, "-trimpath") {
			continue
		}
		out = append(out, c.finding("PB915", Warn,
			"go %s without -trimpath embeds $srcdir paths in the binary, so builds are not reproducible and leak the build layout", c.Subcommand()))
	}
	return out
}

// --- PB916: module cache written read-only ------------------------------------

func checkGoModcacheRW(ctx *Context) []Finding {
	goflags := assignmentsTo(ctx, "GOFLAGS")
	var out []Finding
	for _, c := range goModuleCommands(ctx) {
		if goFlagAddressed(goflags, c, "-modcacherw") {
			continue
		}
		out = append(out, c.finding("PB916", Info,
			"go %s writes a read-only module cache; without -modcacherw, cleaning the build directory needs a chmod first", c.Subcommand()))
	}
	return out
}

// --- PB917: hardening flags never reach cgo ------------------------------------

// cgoFlagVars are the variables that forward the exported toolchain flags to
// cgo-compiled code; any one of them being set counts as the PKGBUILD having
// made the call.
var cgoFlagVars = []string{"CGO_CPPFLAGS", "CGO_CFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS"}

func checkGoCgoFlags(ctx *Context) []Finding {
	cmds := goBuildCommands(ctx)
	if len(cmds) == 0 {
		return nil
	}
	for _, name := range cgoFlagVars {
		if len(assignmentsTo(ctx, name)) > 0 {
			return nil
		}
	}
	for _, v := range assignmentsTo(ctx, "CGO_ENABLED") {
		if strings.TrimSpace(v) == "0" {
			return nil // cgo is off; there is nothing to forward
		}
	}
	// One finding per PKGBUILD: the remedy is a block of exports, not a
	// per-command flag.
	return []Finding{cmds[0].finding("PB917", Info,
		"CFLAGS/LDFLAGS are not forwarded to cgo: without CGO_CFLAGS/CGO_LDFLAGS exports, Arch's hardening flags never reach C code in this build; export them or set CGO_ENABLED=0")}
}
