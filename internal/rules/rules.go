// Package rules implements pkglint's security and hygiene checks over
// statically parsed PKGBUILDs and install scriptlets.
package rules

import (
	"fmt"
	"sort"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

// Severity of a finding.
type Severity int

const (
	Info Severity = iota
	Warn
	Error
	Critical
)

var severityNames = map[Severity]string{Info: "info", Warn: "warn", Error: "error", Critical: "critical"}

func (s Severity) String() string { return severityNames[s] }

// ParseSeverity converts a name to a Severity.
func ParseSeverity(name string) (Severity, error) {
	for sev, n := range severityNames {
		if n == name {
			return sev, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q", name)
}

// MarshalJSON renders severities as their names.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Finding is a single reported issue.
type Finding struct {
	RuleID   string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Path     string   `json:"path"`
	Line     int      `json:"line"`
	Col      int      `json:"col"`
}

// Rule is a single check.
type Rule struct {
	ID    string
	Name  string // short slug, e.g. "unpinned-vcs-source"
	Doc   string // one-paragraph explanation, rendered on the report card site
	Check func(*Context) []Finding

	// FixLevel classifies the rule's auto-fix (FixNone when it has none); Fix
	// computes the edits. A FixSafe fix runs under --fix, a FixUnsafe fix only
	// under --unsafe-fix.
	FixLevel FixLevel
	Fix      Fixer

	// Bad and Good are illustrative PKGBUILD snippets shown on the report
	// card site: Bad is a construct the rule flags, Good the preferred
	// alternative. Attached from the examples table in Registry().
	Bad  string
	Good string
}

// Context carries the package under analysis plus precomputed command
// information shared by rules.
type Context struct {
	Pkg  *pkgbuild.Package
	cmds []Command
	vars map[string]string
}

// Command is one resolved command invocation anywhere in a unit (including
// inside command substitutions).
type Command struct {
	Unit    *pkgbuild.Unit
	Fn      string // enclosing function name; "" for top-level code
	Stmt    *syntax.Stmt
	Call    *syntax.CallExpr
	Name    string // resolved command name; "" when not statically resolvable
	RawName string // rendered first word, for messages
	Dynamic bool   // command name contains unresolvable constructs
	Args    []string
	ArgDyn  []bool
}

// NewContext precomputes shared state for rules.
func NewContext(pkg *pkgbuild.Package) *Context {
	ctx := &Context{Pkg: pkg, vars: map[string]string{}}
	for name, v := range pkg.Vars {
		if !v.Array && len(v.Values) == 1 {
			ctx.vars[name] = pkg.Expand(v.Values[0])
		}
	}
	units := pkg.Units()
	for i := range units {
		u := &units[i]
		names := make([]string, 0, len(u.Functions))
		for name := range u.Functions {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			ctx.collect(u, name, u.Functions[name].Body)
		}
		for _, stmt := range u.TopLevel {
			ctx.collect(u, "", stmt)
		}
	}
	return ctx
}

func (ctx *Context) collect(u *pkgbuild.Unit, fn string, root *syntax.Stmt) {
	syntax.Walk(root, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		ctx.cmds = append(ctx.cmds, ctx.newCommand(u, fn, stmt, call))
		return true
	})
}

// wrappers whose next non-flag argument is the real command.
var wrappers = map[string]bool{
	"env": true, "nice": true, "ionice": true, "nohup": true, "timeout": true,
	"stdbuf": true, "eatmydata": true, "setsid": true, "command": true,
	"exec": true, "builtin": true, "sudo": true, "doas": true,
}

func (ctx *Context) newCommand(u *pkgbuild.Unit, fn string, stmt *syntax.Stmt, call *syntax.CallExpr) Command {
	cmd := Command{Unit: u, Fn: fn, Stmt: stmt, Call: call}
	args := call.Args
	for len(args) > 0 {
		name, dyn := pkgbuild.RenderWord(args[0], ctx.vars)
		if cmd.RawName == "" {
			cmd.RawName = name
		}
		if dyn || hasVarRef(name) {
			cmd.Dynamic = dyn
			cmd.Name = ""
			args = args[1:]
			break
		}
		base := basename(name)
		if wrappers[base] {
			args = args[1:]
			// Skip the wrapper's flags and VAR=val words.
			for len(args) > 0 {
				s, d := pkgbuild.RenderWord(args[0], ctx.vars)
				if !d && (hasPrefixAny(s, "-") || isAssignWord(s)) {
					args = args[1:]
					continue
				}
				break
			}
			continue
		}
		cmd.Name = base
		args = args[1:]
		break
	}
	for _, w := range args {
		s, dyn := pkgbuild.RenderWord(w, ctx.vars)
		cmd.Args = append(cmd.Args, s)
		cmd.ArgDyn = append(cmd.ArgDyn, dyn)
	}
	return cmd
}

// Commands returns every command; optional filters restrict the results.
func (ctx *Context) Commands() []Command { return ctx.cmds }

// CommandsNamed returns commands with a resolved name in names.
func (ctx *Context) CommandsNamed(names ...string) []Command {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	var out []Command
	for _, c := range ctx.cmds {
		if set[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// HasArg reports whether the command has an argument exactly equal to s.
func (c Command) HasArg(s string) bool {
	for _, a := range c.Args {
		if a == s {
			return true
		}
	}
	return false
}

// HasArgPrefix reports whether any argument starts with prefix.
func (c Command) HasArgPrefix(prefix string) bool {
	for _, a := range c.Args {
		if hasPrefixAny(a, prefix) {
			return true
		}
	}
	return false
}

// Subcommand returns the first argument that does not look like a flag.
func (c Command) Subcommand() string {
	for _, a := range c.Args {
		if !hasPrefixAny(a, "-") {
			return a
		}
	}
	return ""
}

// InBuildPhase reports whether the command runs in build(), check(),
// package() or a split package_*() function of a PKGBUILD.
func (c Command) InBuildPhase() bool {
	if c.Unit.Scriptlet {
		return false
	}
	return c.Fn == "build" || c.Fn == "check" || c.Fn == "package" || hasPrefixAny(c.Fn, "package_")
}

func (c Command) finding(id string, sev Severity, format string, args ...any) Finding {
	pos := c.Stmt.Pos()
	return Finding{
		RuleID:   id,
		Severity: sev,
		Message:  fmt.Sprintf(format, args...),
		Path:     c.Unit.Path,
		Line:     int(pos.Line()),
		Col:      int(pos.Col()),
	}
}

func findingAt(id string, sev Severity, path string, pos syntax.Pos, format string, args ...any) Finding {
	return Finding{
		RuleID:   id,
		Severity: sev,
		Message:  fmt.Sprintf(format, args...),
		Path:     path,
		Line:     int(pos.Line()),
		Col:      int(pos.Col()),
	}
}

// Registry is every rule, in ID order.
func Registry() []Rule {
	all := [][]Rule{integrityRules, hermeticRules, execRules, fsRules, scriptletRules, consistencyRules, correctnessRules}
	var out []Rule
	for _, group := range all {
		out = append(out, group...)
	}
	for i := range out {
		if ex, ok := examples[out[i].ID]; ok {
			out[i].Bad = ex.Bad
			out[i].Good = ex.Good
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Run executes every rule not in ignore and returns findings, dropping ones
// suppressed by inline directives, sorted by file position.
func Run(pkg *pkgbuild.Package, ignore map[string]bool) []Finding {
	ctx := NewContext(pkg)
	var out []Finding
	for _, rule := range Registry() {
		if ignore[rule.ID] {
			continue
		}
		for _, f := range rule.Check(ctx) {
			if pkg.Suppressed(f.RuleID, f.Line) {
				continue
			}
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
	return out
}

// RuleByID returns the rule with the given ID.
func RuleByID(id string) (Rule, bool) {
	for _, r := range Registry() {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
