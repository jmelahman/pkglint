package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

// FixLevel classifies how aggressive a rule's auto-fix is.
type FixLevel int

const (
	// FixNone means the rule has no auto-fix.
	FixNone FixLevel = iota
	// FixSafe fixes are deterministic rewrites that preserve intended behavior
	// or restore a security default. They are applied by --fix.
	FixSafe
	// FixUnsafe fixes are mechanical but behavior-changing, so they need
	// review. They are applied only by --unsafe-fix (which implies --fix).
	FixUnsafe
)

// Fixable reports whether the level has an auto-fix at all.
func (l FixLevel) Fixable() bool { return l == FixSafe || l == FixUnsafe }

// Safe reports whether the fix is behavior-preserving (applied by --fix).
func (l FixLevel) Safe() bool { return l == FixSafe }

// Flag is the CLI flag that applies fixes at this level (empty when none).
func (l FixLevel) Flag() string {
	switch l {
	case FixSafe:
		return "--fix"
	case FixUnsafe:
		return "--unsafe-fix"
	default:
		return ""
	}
}

// Edit is a byte-range replacement within a single unit's Raw source. Start
// and End are byte offsets into that unit's Raw; Start == End is an insertion.
type Edit struct {
	Path   string
	Start  int
	End    int
	New    string
	Line   int // 1-based line of the change, for inline-suppression checks
	RuleID string
	Desc   string // human-readable description of what changed
}

// FixEnv carries capabilities a fixer needs but must not perform itself (for
// example, network access). The caller supplies it only when a fix is
// requested.
type FixEnv struct {
	// ResolveRef maps a VCS URL and a mutable ref (a tag or branch name) to an
	// immutable commit hash. It is nil when resolution is unavailable (e.g.
	// offline); a fixer that needs it then emits no edit and the finding
	// stands. Implementations run `git ls-remote` or similar — network I/O the
	// rules package deliberately delegates to the caller.
	ResolveRef func(url, ref string) (string, error)
}

// Fixer computes edits that resolve a rule's findings. It returns nil for
// occurrences it cannot fix safely.
type Fixer func(*Context, *FixEnv) []Edit

// FixResult is the outcome of applying edits to one unit.
type FixResult struct {
	Path     string
	Original []byte
	Fixed    []byte
	Applied  []Edit // in original file order
}

// Changed reports whether the fix altered the unit.
func (r FixResult) Changed() bool { return !bytes.Equal(r.Original, r.Fixed) }

// CollectEdits runs every eligible fixer and returns the edits it proposes,
// excluding rules in ignore, occurrences suppressed inline, and fixes above
// the requested level.
func CollectEdits(ctx *Context, ignore map[string]bool, level FixLevel, env *FixEnv) []Edit {
	if env == nil {
		env = &FixEnv{}
	}
	var edits []Edit
	for _, rule := range Registry() {
		if rule.Fix == nil || rule.FixLevel == FixNone || rule.FixLevel > level || ignore[rule.ID] {
			continue
		}
		for _, e := range rule.Fix(ctx, env) {
			e.RuleID = rule.ID
			if ctx.Pkg.Suppressed(rule.ID, e.Line) {
				continue
			}
			edits = append(edits, e)
		}
	}
	return edits
}

// Fix computes and applies auto-fixes for a package at the given level,
// returning one FixResult per unit that had edits applied.
func Fix(pkg *pkgbuild.Package, ignore map[string]bool, level FixLevel, env *FixEnv) []FixResult {
	ctx := NewContext(pkg)
	byPath := map[string][]Edit{}
	for _, e := range CollectEdits(ctx, ignore, level, env) {
		byPath[e.Path] = append(byPath[e.Path], e)
	}
	var results []FixResult
	for _, u := range pkg.Units() {
		es := byPath[u.Path]
		if len(es) == 0 {
			continue
		}
		fixed, applied := ApplyEdits(u.Raw, es)
		results = append(results, FixResult{Path: u.Path, Original: u.Raw, Fixed: fixed, Applied: applied})
	}
	return results
}

// ApplyEdits applies edits (all addressing the same raw source) and returns
// the rewritten bytes plus the edits actually applied, in file order.
// Overlapping edits are resolved by keeping the earlier-starting one.
func ApplyEdits(raw []byte, edits []Edit) (result []byte, applied []Edit) {
	sorted := append([]Edit(nil), edits...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End < sorted[j].End
	})
	var kept []Edit
	lastEnd := 0
	for _, e := range sorted {
		if e.Start < 0 || e.End > len(raw) || e.Start > e.End {
			continue
		}
		if len(kept) > 0 && e.Start < lastEnd {
			continue // overlaps an already-kept edit
		}
		kept = append(kept, e)
		lastEnd = e.End
	}
	out := raw
	for i := len(kept) - 1; i >= 0; i-- {
		e := kept[i]
		var buf []byte
		buf = append(buf, out[:e.Start]...)
		buf = append(buf, e.New...)
		buf = append(buf, out[e.End:]...)
		out = buf
	}
	return out, kept
}

// off is the byte offset of a position, as an int.
func off(p syntax.Pos) int { return int(p.Offset()) }

// wordByValue returns the first argument word of c whose statically rendered
// value equals val, or nil.
func wordByValue(c Command, val string) *syntax.Word {
	if val == "" {
		return nil
	}
	for _, w := range c.Call.Args {
		if s, _ := pkgbuild.RenderWord(w, nil); s == val {
			return w
		}
	}
	return nil
}

// --- PB103: pin a mutable VCS ref to a commit ------------------------------

var commitHashRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

func fixVCSPins(ctx *Context, env *FixEnv) []Edit {
	if env == nil || env.ResolveRef == nil {
		return nil // offline: the finding stands with its suggestion
	}
	elems := sourceElems(&ctx.Pkg.PKGBUILD)
	var edits []Edit
	for _, e := range ctx.Pkg.Sources() {
		if e.VCS != "git" {
			continue // only git refs are resolvable with `git ls-remote`
		}
		if _, ok := e.Fragment["commit"]; ok {
			continue
		}
		if _, ok := e.Fragment["revision"]; ok {
			continue
		}
		var fragKey, refVal string
		if tag, ok := e.Fragment["tag"]; ok {
			if strings.Contains(e.Query, "signed") {
				continue
			}
			fragKey, refVal = "tag", tag
		} else if br, ok := e.Fragment["branch"]; ok {
			fragKey, refVal = "branch", br
		} else {
			continue // no named ref to resolve into a commit deterministically
		}
		w := elems[elemKey(e.Arch, e.Index)]
		if w == nil {
			continue
		}
		raw := string(ctx.Pkg.PKGBUILD.Raw[off(w.Pos()):off(w.End())])
		needle := "#" + fragKey + "=" + refVal
		if !strings.Contains(raw, needle) {
			continue // the ref came from a variable; can't rewrite in place
		}
		sha, err := env.ResolveRef(e.URL, refVal)
		if err != nil || !commitHashRe.MatchString(sha) {
			continue
		}
		edits = append(edits, Edit{
			Path:  ctx.Pkg.PKGBUILD.Path,
			Start: off(w.Pos()),
			End:   off(w.End()),
			New:   strings.Replace(raw, needle, "#commit="+sha, 1),
			Line:  int(w.Pos().Line()),
			Desc:  fmt.Sprintf("pin %s %q to commit %s", fragKey, refVal, shortSHA(sha)),
		})
	}
	return edits
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func elemKey(arch string, idx int) string { return arch + "\x00" + strconv.Itoa(idx) }

// sourceElems maps each source-array element to its AST word, keyed the same
// way as SourceEntry's Arch/Index so findings can be matched back to source.
func sourceElems(u *pkgbuild.Unit) map[string]*syntax.Word {
	out := map[string]*syntax.Word{}
	record := func(as *syntax.Assign) {
		if as == nil || as.Name == nil || as.Array == nil {
			return
		}
		name := as.Name.Value
		if name != "source" && !strings.HasPrefix(name, "source_") {
			return
		}
		arch := strings.TrimPrefix(strings.TrimPrefix(name, "source"), "_")
		for i, el := range as.Array.Elems {
			out[elemKey(arch, i)] = el.Value
		}
	}
	for _, stmt := range u.TopLevel {
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Args) == 0 {
				for _, as := range cmd.Assigns {
					record(as)
				}
			}
		case *syntax.DeclClause:
			for _, as := range cmd.Args {
				record(as)
			}
		}
	}
	return out
}

// --- PB203: cargo without --locked -----------------------------------------

func fixCargoLocked(ctx *Context, _ *FixEnv) []Edit {
	var edits []Edit
	for _, c := range ctx.CommandsNamed("cargo") {
		switch c.Subcommand() {
		case "build", "install", "fetch", "test", "rustc":
		default:
			continue
		}
		if c.HasArg("--locked") || c.HasArg("--frozen") || c.HasArg("--offline") {
			continue
		}
		at := off(c.Call.End())
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: at,
			End:   at,
			New:   " --locked",
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  fmt.Sprintf("append --locked to `cargo %s`", c.Subcommand()),
		})
	}
	return edits
}

// --- PB204: implicit go module downloads -----------------------------------

func fixGoDownloads(ctx *Context, _ *FixEnv) []Edit {
	if goVendored(ctx) {
		return nil
	}
	var edits []Edit
	for _, c := range ctx.CommandsNamed("go") {
		if !c.InBuildPhase() {
			continue
		}
		sub := c.Subcommand()
		if sub != "build" && sub != "install" && sub != "test" && sub != "run" {
			continue
		}
		if c.HasArg("-mod=vendor") {
			continue
		}
		w := wordByValue(c, sub)
		if w == nil {
			continue
		}
		at := off(w.End())
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: at,
			End:   at,
			New:   " -mod=vendor",
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  fmt.Sprintf("add -mod=vendor to `go %s` (also vendor modules: `go mod vendor` in prepare(), commit vendor/)", sub),
		})
	}
	return edits
}

// --- PB205: re-enable Go module verification -------------------------------

func fixGoEnvWeakening(ctx *Context, _ *FixEnv) []Edit {
	var edits []Edit
	// Inline command prefixes: `GOSUMDB=off go build ...`.
	for _, c := range ctx.Commands() {
		for _, as := range c.Call.Assigns {
			if isGoWeakeningAssign(as) {
				edits = append(edits, removeAssignEdit(c.Unit, as))
			}
		}
	}
	// Standalone top-level assignment statements: `GOSUMDB=off`, `export GOSUMDB=off`.
	u := &ctx.Pkg.PKGBUILD
	for _, stmt := range u.TopLevel {
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Args) == 0 {
				edits = append(edits, assignStmtEdits(u, stmt, cmd.Assigns)...)
			}
		case *syntax.DeclClause:
			edits = append(edits, assignStmtEdits(u, stmt, cmd.Args)...)
		}
	}
	return edits
}

func isGoWeakeningAssign(as *syntax.Assign) bool {
	if as == nil || as.Name == nil {
		return false
	}
	_, bad := goEnvWeakens(as.Name.Value, assignValue(as))
	return bad
}

func assignValue(as *syntax.Assign) string {
	if as == nil || as.Value == nil {
		return ""
	}
	s, _ := renderPlain(as.Value)
	return s
}

// assignStmtEdits removes the Go-weakening assignments in a pure assignment
// statement: the whole statement if all its assignments are weakening, else
// each weakening assignment individually.
func assignStmtEdits(u *pkgbuild.Unit, stmt *syntax.Stmt, assigns []*syntax.Assign) []Edit {
	var bad []*syntax.Assign
	for _, as := range assigns {
		if isGoWeakeningAssign(as) {
			bad = append(bad, as)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	if len(bad) == len(assigns) {
		return []Edit{removeStmtLine(u, stmt, bad[0].Name.Value)}
	}
	edits := make([]Edit, 0, len(bad))
	for _, as := range bad {
		edits = append(edits, removeAssignEdit(u, as))
	}
	return edits
}

func removeAssignEdit(u *pkgbuild.Unit, as *syntax.Assign) Edit {
	start, end := off(as.Pos()), off(as.End())
	for end < len(u.Raw) && (u.Raw[end] == ' ' || u.Raw[end] == '\t') {
		end++
	}
	return Edit{
		Path:  u.Path,
		Start: start,
		End:   end,
		New:   "",
		Line:  int(as.Pos().Line()),
		Desc:  fmt.Sprintf("remove %s (re-enables Go module verification)", as.Name.Value),
	}
}

func removeStmtLine(u *pkgbuild.Unit, stmt *syntax.Stmt, name string) Edit {
	start, end := off(stmt.Pos()), off(stmt.End())
	ls := start
	for ls > 0 && (u.Raw[ls-1] == ' ' || u.Raw[ls-1] == '\t') {
		ls--
	}
	if ls == 0 || u.Raw[ls-1] == '\n' { // only indentation precedes: take the line
		start = ls
		for end < len(u.Raw) && (u.Raw[end] == ' ' || u.Raw[end] == '\t') {
			end++
		}
		if end < len(u.Raw) && u.Raw[end] == '\n' {
			end++
		}
	}
	return Edit{
		Path:  u.Path,
		Start: start,
		End:   end,
		New:   "",
		Line:  int(stmt.Pos().Line()),
		Desc:  fmt.Sprintf("remove %s assignment (re-enables Go module verification)", name),
	}
}

// --- PB206: npm/yarn lockfile-faithful install -----------------------------

func fixNpmCI(ctx *Context, _ *FixEnv) []Edit {
	var edits []Edit
	for _, c := range ctx.CommandsNamed("npm") {
		sub := c.Subcommand()
		if sub != "install" && sub != "i" {
			continue
		}
		if npmHasPackageArg(c) {
			continue // `npm install <pkg>` is not equivalent to `npm ci`
		}
		w := wordByValue(c, sub)
		if w == nil {
			continue
		}
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: off(w.Pos()),
			End:   off(w.End()),
			New:   "ci",
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  fmt.Sprintf("replace `npm %s` with `npm ci` (installs exactly the committed lockfile)", sub),
		})
	}
	for _, c := range ctx.CommandsNamed("yarn") {
		if sub := c.Subcommand(); sub != "install" && sub != "" {
			continue
		}
		if c.HasArg("--immutable") || c.HasArg("--frozen-lockfile") {
			continue
		}
		at := off(c.Call.End())
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: at,
			End:   at,
			New:   " --immutable",
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  "append --immutable to `yarn install`",
		})
	}
	for _, name := range []string{"pnpm", "bun"} {
		for _, c := range ctx.CommandsNamed(name) {
			sub := c.Subcommand()
			if sub != "install" && sub != "i" {
				continue
			}
			// With package args the command adds a dependency; freezing the
			// lockfile is not equivalent.
			if c.HasArg("--frozen-lockfile") || c.HasArg("--offline") || npmHasPackageArg(c) {
				continue
			}
			at := off(c.Call.End())
			edits = append(edits, Edit{
				Path:  c.Unit.Path,
				Start: at,
				End:   at,
				New:   " --frozen-lockfile",
				Line:  int(c.Stmt.Pos().Line()),
				Desc:  fmt.Sprintf("append --frozen-lockfile to `%s %s`", name, sub),
			})
		}
	}
	return edits
}

// --- PB207: composer without --no-scripts ----------------------------------

func fixComposer(ctx *Context, _ *FixEnv) []Edit {
	var edits []Edit
	for _, c := range ctx.CommandsNamed("composer") {
		if c.Subcommand() != "install" || c.HasArg("--no-scripts") {
			continue
		}
		at := off(c.Call.End())
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: at,
			End:   at,
			New:   " --no-scripts",
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  "append --no-scripts to `composer install`",
		})
	}
	return edits
}

// --- PB208: bundle install without --frozen --------------------------------

func fixBundler(ctx *Context, _ *FixEnv) []Edit {
	var edits []Edit
	for _, c := range ctx.CommandsNamed("bundle", "bundler") {
		if c.Subcommand() != "install" { // leave bare `bundle` alone
			continue
		}
		if c.HasArg("--frozen") || c.HasArg("--deployment") || c.HasArg("--local") {
			continue
		}
		at := off(c.Call.End())
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: at,
			End:   at,
			New:   " --frozen",
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  "append --frozen to `bundle install`",
		})
	}
	return edits
}

// --- PB209: uv sync without --frozen ----------------------------------------

func fixUvFrozen(ctx *Context, _ *FixEnv) []Edit {
	var edits []Edit
	for _, c := range ctx.CommandsNamed("uv") {
		// Only `uv sync`: for `uv run` a trailing flag would land on the
		// command being run, not on uv.
		if c.Subcommand() != "sync" {
			continue
		}
		if c.HasArg("--frozen") || c.HasArg("--locked") || c.HasArg("--offline") || c.HasArg("--no-sync") {
			continue
		}
		at := off(c.Call.End())
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: at,
			End:   at,
			New:   " --frozen",
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  "append --frozen to `uv sync`",
		})
	}
	return edits
}

func npmHasPackageArg(c Command) bool {
	seenSub := false
	for _, a := range c.Args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if !seenSub {
			seenSub = true
			continue
		}
		return true
	}
	return false
}

// --- PB403: drop setuid/setgid mode bits -----------------------------------

func fixSetuid(ctx *Context, _ *FixEnv) []Edit {
	var edits []Edit
	for _, c := range ctx.CommandsNamed("chmod") {
		for _, a := range c.Args {
			if !setuidNumericMode(a) {
				continue
			}
			w := wordByValue(c, a)
			if w == nil {
				break
			}
			cleaned := clearSetuidBits(a)
			if cleaned == a {
				break
			}
			edits = append(edits, Edit{
				Path:  c.Unit.Path,
				Start: off(w.Pos()),
				End:   off(w.End()),
				New:   cleaned,
				Line:  int(c.Stmt.Pos().Line()),
				Desc:  fmt.Sprintf("drop setuid/setgid bit: chmod %s → %s", a, cleaned),
			})
			break
		}
	}
	for _, c := range ctx.CommandsNamed("install") {
		mode, w, replacement := installModeArg(c)
		if !setuidNumericMode(mode) || w == nil || replacement == mode {
			continue
		}
		orig, _ := pkgbuild.RenderWord(w, nil)
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: off(w.Pos()),
			End:   off(w.End()),
			New:   replacement,
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  fmt.Sprintf("drop setuid/setgid bit: install %s → %s", orig, replacement),
		})
	}
	return edits
}

func clearSetuidBits(mode string) string {
	v, err := strconv.ParseInt(mode, 8, 32)
	if err != nil {
		return mode
	}
	v &^= 0o6000 // clear setuid and setgid, keep sticky and permission bits
	return fmt.Sprintf("%04o", v)
}
