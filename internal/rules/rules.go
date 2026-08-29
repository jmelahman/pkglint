// Package rules implements pkglint's security and hygiene checks over
// statically parsed PKGBUILDs and install scriptlets.
package rules

import (
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/jmelahman/pkglint/internal/alpmdb"
	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"github.com/jmelahman/pkglint/internal/pkgfile"
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

// UnmarshalJSON reads back what MarshalJSON wrote. Without it a Finding is
// write-only over JSON: it encodes to a name and then refuses to decode,
// because the underlying int has no idea what "warn" means.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	sev, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = sev
	return nil
}

// SeverityRange is the span of severities one rule can report: Low is what it
// reports by default, High the worst it escalates to. The two are equal for
// the rules whose severity does not depend on what they find.
type SeverityRange struct {
	Low, High Severity
}

// Varies reports whether the rule's severity depends on what it found, i.e.
// whether the range covers more than one severity.
func (r SeverityRange) Varies() bool { return r.High > r.Low }

// Severities returns the range of severities the rule can report. It resolves
// an unset MaxSeverity, which is indistinguishable from Info (the zero value),
// to a fixed range at Severity.
func (r Rule) Severities() SeverityRange {
	if r.MaxSeverity > r.Severity {
		return SeverityRange{Low: r.Severity, High: r.MaxSeverity}
	}
	return SeverityRange{Low: r.Severity, High: r.Severity}
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

// Scope says which kind of input a rule analyzes.
type Scope int

const (
	// ScopePKGBUILD rules run over a package directory: the PKGBUILD and the
	// install scriptlets committed next to it.
	ScopePKGBUILD Scope = iota
	// ScopePackage rules run over a built package archive (.pkg.tar.*).
	ScopePackage
)

// Rule is a single check.
type Rule struct {
	ID    string
	Name  string // short slug, e.g. "unpinned-vcs-source"
	Scope Scope

	// Severity is what the rule reports. A handful of rules escalate on what
	// they find — an eval of a downloaded script is worse than a plain eval —
	// and set MaxSeverity to the worst they can reach; it is left unset when
	// the severity is fixed. Read the pair through Severities, which resolves
	// that zero value. Both are declarations *about* Check, not inputs to it:
	// the findings carry their own severity, and TestRuleSeveritiesAreDeclared
	// holds the two in agreement.
	Severity    Severity
	MaxSeverity Severity

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
// information shared by rules. Exactly one of Pkg (a PKGBUILD package
// directory) and File (a built package archive) drives a given run.
type Context struct {
	Pkg  *pkgbuild.Package
	File *pkgfile.Package // built package under analysis, for ScopePackage rules
	DB   *alpmdb.DB       // pacman local database; nil when unavailable
	cmds []Command
	vars map[string]string
	// splitVars caches per-split-package variants of vars where pkgname is
	// bound to that split's name, matching how makepkg runs package_<name>().
	splitVars map[string]map[string]string

	pkgFacts *packageFacts // lazily computed facts shared by package rules
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
	ctx := &Context{Pkg: pkg, vars: map[string]string{}, splitVars: map[string]map[string]string{}}
	for name, v := range pkg.Vars {
		// Scalars render to exactly one value; for arrays, bash expands an
		// unsubscripted $name to the first element (and an empty array to "").
		if len(v.Values) > 0 {
			ctx.vars[name] = pkg.Expand(v.Values[0])
		} else if v.Array {
			ctx.vars[name] = ""
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

// varsFor returns the variable map for rendering words inside fn. makepkg
// runs each split's package_<name>() with pkgname rebound to that split, so
// inside those functions $pkgname is the split's own name rather than the
// pkgname array's first element.
func (ctx *Context) varsFor(fn string) map[string]string {
	split, ok := strings.CutPrefix(fn, "package_")
	if !ok {
		return ctx.vars
	}
	if m, ok := ctx.splitVars[split]; ok {
		return m
	}
	v, ok := ctx.Pkg.Vars["pkgname"]
	if !ok || !v.Array {
		return ctx.vars
	}
	declared := false
	for _, val := range v.Values {
		if ctx.Pkg.Expand(val) == split {
			declared = true
			break
		}
	}
	if !declared {
		return ctx.vars
	}
	m := make(map[string]string, len(ctx.vars))
	maps.Copy(m, ctx.vars)
	m["pkgname"] = split
	ctx.splitVars[split] = m
	return m
}

func (ctx *Context) newCommand(u *pkgbuild.Unit, fn string, stmt *syntax.Stmt, call *syntax.CallExpr) Command {
	cmd := Command{Unit: u, Fn: fn, Stmt: stmt, Call: call}
	vars := ctx.varsFor(fn)
	args := call.Args
	for len(args) > 0 {
		name, dyn := pkgbuild.RenderWord(args[0], vars)
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
				s, d := pkgbuild.RenderWord(args[0], vars)
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
		s, dyn := pkgbuild.RenderWord(w, vars)
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
	all := [][]Rule{integrityRules, hermeticRules, execRules, fsRules, scriptletRules, consistencyRules, correctnessRules, packageRules, styleRules}
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

// Run executes every PKGBUILD-scope rule not in ignore and returns findings,
// dropping ones suppressed by inline directives. The result is totally ordered
// by (Path, Line, Col, RuleID, Message) and free of exact duplicates, so the
// same package always lints to the same list.
func Run(pkg *pkgbuild.Package, ignore map[string]bool) []Finding {
	ctx := NewContext(pkg)
	var out []Finding
	for _, rule := range Registry() {
		if rule.Scope != ScopePKGBUILD || ignore[rule.ID] {
			continue
		}
		for _, f := range rule.Check(ctx) {
			if pkg.Suppressed(f.RuleID, f.Path, f.Line) {
				continue
			}
			out = append(out, f)
		}
	}
	return sortDedupe(out)
}

// RunPackage executes every package-scope rule over a built package archive,
// plus the scriptlet rules over the archive's .INSTALL if it has one. db may
// be nil, in which case the rules that need dependency resolution do not run.
func RunPackage(pf *pkgfile.Package, db *alpmdb.DB, ignore map[string]bool) []Finding {
	ctx := &Context{File: pf, DB: db, vars: map[string]string{}}
	var out []Finding
	for _, rule := range Registry() {
		if rule.Scope != ScopePackage || ignore[rule.ID] {
			continue
		}
		out = append(out, rule.Check(ctx)...)
	}
	out = append(out, runPackageScriptlet(pf, ignore)...)
	return sortDedupe(out)
}

// runPackageScriptlet runs the PKGBUILD-scope rules over the archive's
// .INSTALL scriptlet, keeping only the findings anchored in the scriptlet
// itself. This gives built packages the same install-time analysis (network,
// persistence, obfuscation, hook redundancy) a package directory gets.
func runPackageScriptlet(pf *pkgfile.Package, ignore map[string]bool) []Finding {
	install := pf.Entry(".INSTALL")
	if install == nil || len(install.Data) == 0 {
		return nil
	}
	const path = ".INSTALL"
	pseudo := &pkgbuild.Package{
		Vars:         map[string]*pkgbuild.Var{},
		Suppressions: map[string]map[int]map[string]bool{},
	}
	// Rules walk every unit including the PKGBUILD; give the pseudo-package an
	// empty-but-parsed one so nothing trips over a nil AST.
	if empty, err := pkgbuild.ParseScriptlet("", nil); err == nil {
		empty.Scriptlet = false
		pseudo.PKGBUILD = empty
	}
	if unit, err := pkgbuild.ParseScriptlet(path, install.Data); err != nil {
		pseudo.ScriptletErrors = []pkgbuild.ScriptletError{{Path: path, Err: err.Error()}}
	} else {
		pseudo.Scriptlets = []pkgbuild.Unit{unit}
	}
	ctx := NewContext(pseudo)
	var out []Finding
	for _, rule := range Registry() {
		if rule.Scope != ScopePKGBUILD || ignore[rule.ID] {
			continue
		}
		for _, f := range rule.Check(ctx) {
			// Rules that judge the (empty) pseudo-PKGBUILD report at other
			// paths; only the scriptlet's own findings are real here.
			if f.Path == path {
				out = append(out, f)
			}
		}
	}
	return out
}

func sortDedupe(out []Finding) []Finding {
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Message < b.Message
	})
	// Drop exact duplicates (same rule + location + message). After a total
	// sort, duplicates are adjacent. This de-noises rules that can emit the
	// same finding twice (e.g. overlapping persistence-path hints).
	if len(out) > 1 {
		deduped := out[:1]
		for _, f := range out[1:] {
			last := deduped[len(deduped)-1]
			if f.RuleID == last.RuleID && f.Path == last.Path && f.Line == last.Line &&
				f.Col == last.Col && f.Message == last.Message {
				continue
			}
			deduped = append(deduped, f)
		}
		out = deduped
	}
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
