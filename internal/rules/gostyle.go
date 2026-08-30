package rules

import (
	"sort"
	"strings"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

// PB914–PB917 lint the build-flag conventions of the Arch Linux Go package
// guidelines (https://wiki.archlinux.org/title/Go_package_guidelines): PIE
// hardening, reproducible paths, a writable module cache, and toolchain flags
// reaching cgo. The guidelines' module-download and verification advice is
// hermeticity and already covered by PB204/PB205; `-mod=readonly` is not
// linted because it has been Go's default since 1.16.

// assignmentsTo returns the rendered value of every assignment to name that
// has taken effect by the time c runs. GOFLAGS and the CGO_* variables reach
// the toolchain through the environment, so their scope is makepkg's rather
// than the file's: a top-level assignment is sourced before every phase, an
// assignment inside a phase function reaches that function's later commands
// and the phases makepkg runs after it — never one it has already finished —
// and a command's own environment prefix reaches nothing but that command.
// An `export GOFLAGS=-modcacherw` in build() therefore says nothing about the
// `go mod download` prepare() already ran.
//
// Dynamic parts render as their literal fragments, so `GOFLAGS="$GOFLAGS
// -trimpath"` still reveals the appended flag; values that are entirely
// dynamic render empty but still count as an assignment.
func assignmentsTo(ctx *Context, name string, c Command) []string {
	at := -1
	if c.Stmt != nil {
		at = off(c.Stmt.Pos())
	}
	return assignmentsInScope(c.Unit, name, c.Fn, at, c.Call)
}

// assignmentsInScope is assignmentsTo addressed by position instead of by
// command, so a fix can ask what a line it is about to write would inherit.
// Assignments in fn count only when they start before at (negative: all of
// them); own names the CallExpr whose environment prefix belongs to the
// caller, if any.
func assignmentsInScope(u *pkgbuild.Unit, name, fn string, at int, own *syntax.CallExpr) []string {
	if u == nil || u.Scriptlet {
		return nil
	}
	visible := map[string]bool{}
	for _, p := range precedingPhases(fn) {
		visible[p] = true
	}
	// The caller's own environment prefix sits at the caller's position, so
	// it is exempt from the "must start before at" cutoff below.
	ownAssigns := map[*syntax.Assign]bool{}
	if own != nil {
		for _, as := range own.Assigns {
			ownAssigns[as] = true
		}
	}
	var out []string
	// A subtree contributes every assignment to name except another command's
	// environment prefix. syntax.Walk is pre-order, so a CallExpr is seen
	// before its own assignments and can disown them first.
	scan := func(n syntax.Node, before int) {
		if n == nil {
			return
		}
		foreign := map[*syntax.Assign]bool{}
		syntax.Walk(n, func(node syntax.Node) bool {
			if ce, ok := node.(*syntax.CallExpr); ok && ce != own {
				for _, as := range ce.Assigns {
					foreign[as] = true
				}
				return true
			}
			as, ok := node.(*syntax.Assign)
			if !ok || as.Name == nil || as.Name.Value != name || as.Value == nil || foreign[as] {
				return true
			}
			if before >= 0 && off(as.Pos()) >= before && !ownAssigns[as] {
				return true
			}
			s, _ := renderPlain(as.Value)
			out = append(out, s)
			return true
		})
	}
	// Top-level code runs in full before any function does — unless the
	// caller is itself top-level, where only the lines above it have run.
	topLimit := -1
	if fn == "" {
		topLimit = at
	}
	for _, stmt := range u.TopLevel {
		scan(stmt, topLimit)
	}
	names := make([]string, 0, len(u.Functions))
	for n := range u.Functions {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		switch {
		case n == fn:
			scan(u.Functions[n].Body, at)
		case visible[n], !makepkgPhase(n):
			// A helper the PKGBUILD calls itself has no fixed place in the
			// order, so assume it can run before c and count its assignments.
			scan(u.Functions[n].Body, -1)
		}
	}
	return out
}

// makepkgPhase reports whether fn is a function makepkg calls itself, and so
// has a known position in the run order.
func makepkgPhase(fn string) bool {
	if fn == "package" || strings.HasPrefix(fn, "package_") {
		return true
	}
	for _, p := range buildPhases {
		if fn == p {
			return true
		}
	}
	return false
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
	var out []Finding
	for _, c := range goBuildCommands(ctx) {
		if goFlagAddressed(assignmentsTo(ctx, "GOFLAGS", c), c, "-buildmode") {
			continue
		}
		out = append(out, c.finding("PB914", Warn,
			"go %s without -buildmode=pie produces a non-PIE executable, so ASLR cannot relocate it; set it in GOFLAGS or on the command", c.Subcommand()))
	}
	return out
}

// --- PB915: go build without -trimpath ----------------------------------------

func checkGoTrimpath(ctx *Context) []Finding {
	var out []Finding
	for _, c := range goBuildCommands(ctx) {
		if goFlagAddressed(assignmentsTo(ctx, "GOFLAGS", c), c, "-trimpath") {
			continue
		}
		out = append(out, c.finding("PB915", Warn,
			"go %s without -trimpath embeds $srcdir paths in the binary, so builds are not reproducible and leak the build layout", c.Subcommand()))
	}
	return out
}

// --- PB916: module cache written read-only ------------------------------------

func checkGoModcacheRW(ctx *Context) []Finding {
	var out []Finding
	for _, c := range goModuleCommands(ctx) {
		if goFlagAddressed(assignmentsTo(ctx, "GOFLAGS", c), c, "-modcacherw") {
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
	for _, c := range goBuildCommands(ctx) {
		if cgoFlagsForwarded(ctx, c) {
			continue
		}
		// One finding per PKGBUILD: the remedy is a block of exports, not a
		// per-command flag. The first uncovered command carries it.
		return []Finding{c.finding("PB917", Info,
			"CFLAGS/LDFLAGS are not forwarded to cgo: without CGO_CFLAGS/CGO_LDFLAGS exports, Arch's hardening flags never reach C code in this build; export them or set CGO_ENABLED=0")}
	}
	return nil
}

// cgoFlagsForwarded reports whether c inherits the toolchain flags, either
// because a CGO_*FLAGS export reached it or because cgo is off for it.
func cgoFlagsForwarded(ctx *Context, c Command) bool {
	for _, name := range cgoFlagVars {
		if len(assignmentsTo(ctx, name, c)) > 0 {
			return true
		}
	}
	for _, v := range assignmentsTo(ctx, "CGO_ENABLED", c) {
		if strings.TrimSpace(v) == "0" {
			return true // cgo is off; there is nothing to forward
		}
	}
	return false
}
