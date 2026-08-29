// Package pkgbuild statically parses PKGBUILD and .install files.
//
// PKGBUILDs are untrusted input: they must never be sourced or executed
// (even `makepkg --printsrcinfo` runs top-level code). Everything here is
// pure static analysis on the bash AST via mvdan.cc/sh.
package pkgbuild

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Var is a top-level variable assignment in a PKGBUILD.
type Var struct {
	Name   string
	Values []string // rendered values; one element for scalar assignments
	Array  bool
	Pos    syntax.Pos
	Assign *syntax.Assign // underlying AST node, for byte-offset edits
}

// Unit is a single bash file under analysis: the PKGBUILD itself or an
// install scriptlet.
type Unit struct {
	Path      string
	Raw       []byte
	File      *syntax.File
	Scriptlet bool
	Functions map[string]*syntax.FuncDecl
	TopLevel  []*syntax.Stmt // top-level statements that are not function declarations
}

// ScriptletError records an install scriptlet that was present but could not
// be parsed. Such a file is analyzed by no rule yet still runs as root at
// install time, so it must be surfaced rather than silently skipped.
type ScriptletError struct {
	Path string
	Err  string
}

// Package is a fully loaded package directory.
type Package struct {
	Dir        string
	PKGBUILD   Unit
	Scriptlets []Unit
	// ScriptletErrors holds scriptlets that were read but failed to parse.
	ScriptletErrors []ScriptletError
	Vars            map[string]*Var
	SrcInfo         *SrcInfo // nil when no .SRCINFO is present

	// Suppressions maps a file path to that file's inline
	// "# pkglint: ignore=PB123[,PB456]" directives (line number -> rule IDs
	// disabled on that line; a directive applies to the same and next line).
	// Keying by path keeps a directive in one file from suppressing findings in
	// another file that happens to share a line number.
	Suppressions map[string]map[int]map[string]bool
}

// newParser returns a fresh parser per parse: syntax.Parser is not safe for
// concurrent use, and Load is called from concurrent scanners.
func newParser() *syntax.Parser {
	return syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
}

// Load reads the PKGBUILD at path (a file or a directory containing one),
// plus any install scriptlets referenced by install= or living next to it.
func Load(path string) (*Package, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	dir, file := filepath.Split(path)
	if info.IsDir() {
		dir = path
		file = "PKGBUILD"
	}
	pkgPath := filepath.Join(dir, file)

	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, err
	}
	unit, err := parseUnit(pkgPath, raw, false)
	if err != nil {
		return nil, err
	}

	pkg := &Package{
		Dir:      dir,
		PKGBUILD: unit,
		Vars:     map[string]*Var{},
		// Keyed by unit.Path (== pkgPath), the same string findings on the
		// PKGBUILD carry, so Suppressed lookups match exactly.
		Suppressions: map[string]map[int]map[string]bool{unit.Path: parseSuppressions(raw)},
	}
	pkg.extractTopLevel()

	if data, err := os.ReadFile(filepath.Join(dir, ".SRCINFO")); err == nil {
		pkg.SrcInfo = ParseSrcInfo(data)
	}

	for _, name := range pkg.installFiles() {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			continue // missing scriptlet is reported by a rule
		}
		// Record the scriptlet's directives before parsing it. parseSuppressions
		// is a plain byte scan that needs no bash AST, and a scriptlet that fails
		// to parse still has to be able to waive its own PB503 finding (which
		// reports at this path).
		pkg.Suppressions[p] = parseSuppressions(data)
		su, err := parseUnit(p, data, true)
		if err != nil {
			// The file runs as root at install time but no rule can walk it;
			// record it so PB503 can report the blind spot. Keep only the
			// scriptlet's basename in the message: Path already carries the
			// location, and the message is republished verbatim (e.g. by the
			// site generator, which strips prefixes from paths but not
			// messages).
			msg := strings.TrimPrefix(err.Error(), "parse "+p+": ")
			msg = strings.ReplaceAll(msg, p, name)
			pkg.ScriptletErrors = append(pkg.ScriptletErrors, ScriptletError{Path: p, Err: msg})
			continue
		}
		pkg.Scriptlets = append(pkg.Scriptlets, su)
	}
	return pkg, nil
}

// ParseScriptlet parses raw as an install scriptlet unit. It exists for
// callers that get scriptlet bytes from somewhere other than the package
// directory — notably the .INSTALL member of a built package archive.
func ParseScriptlet(path string, raw []byte) (Unit, error) {
	return parseUnit(path, raw, true)
}

func parseUnit(path string, raw []byte, scriptlet bool) (Unit, error) {
	f, err := newParser().Parse(bytes.NewReader(raw), path)
	if err != nil {
		// Bash accepts several constructs that mvdan.cc/sh does not yet
		// parse; rescueParse recovers a position-accurate AST for the known
		// ones rather than leaving the whole file unscanned (see rescue.go).
		if rf := rescueParse(path, raw); rf != nil {
			f = rf
		} else {
			return Unit{}, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	u := Unit{
		Path:      path,
		Raw:       raw,
		File:      f,
		Scriptlet: scriptlet,
		Functions: map[string]*syntax.FuncDecl{},
	}
	for _, stmt := range f.Stmts {
		if fd, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
			u.Functions[fd.Name.Value] = fd
			continue
		}
		u.TopLevel = append(u.TopLevel, stmt)
	}
	return u, nil
}

// extractTopLevel records top-level variable assignments from the PKGBUILD.
func (p *Package) extractTopLevel() {
	record := func(as *syntax.Assign) {
		if as.Name == nil {
			return
		}
		v := &Var{Name: as.Name.Value, Pos: as.Pos(), Assign: as}
		if as.Array != nil {
			v.Array = true
			for _, el := range as.Array.Elems {
				s, _ := RenderWord(el.Value, nil)
				v.Values = append(v.Values, s)
			}
		} else if as.Value != nil {
			s, _ := RenderWord(as.Value, nil)
			v.Values = []string{s}
		}
		// `source+=(...)` appends in bash; overwriting here would hide the
		// original assignment from every rule. Appending to a name that has no
		// prior assignment is a plain assignment, as in bash.
		if as.Append {
			if prev, ok := p.Vars[v.Name]; ok {
				p.Vars[v.Name] = mergeAppend(prev, v)
				return
			}
		}
		p.Vars[v.Name] = v
	}
	for _, stmt := range p.PKGBUILD.TopLevel {
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
}

// mergeAppend combines a prior top-level assignment with a later `+=` append
// to the same name. Values are concatenated in source order, matching bash,
// where `arr+=(x)` appends an element and `str+=x` concatenates text. If
// either side is an array the merged value is an array; that degenerate
// mismatch (`x=1; x+=(a b)`) keeps both sets of values rather than dropping
// any, since a dropped source is a source no rule can see.
//
// The result keeps the *first* assignment's Pos and Assign, so it stays a
// stable identity for byte-offset edits. Consequently auto-fixes and
// per-element positions anchor to the first assignment: appended elements have
// no entry in Assign.Array.Elems and fall back to the array's start position.
func mergeAppend(prev, add *Var) *Var {
	out := &Var{Name: prev.Name, Pos: prev.Pos, Assign: prev.Assign, Array: prev.Array || add.Array}
	if out.Array {
		out.Values = append(append([]string{}, prev.Values...), add.Values...)
	} else {
		out.Values = []string{strings.Join(prev.Values, "") + strings.Join(add.Values, "")}
	}
	return out
}

// Scalar returns the rendered value of a scalar variable, expanded against
// other known scalars.
func (p *Package) Scalar(name string) (string, bool) {
	v, ok := p.Vars[name]
	if !ok || v.Array || len(v.Values) != 1 {
		return "", false
	}
	return p.Expand(v.Values[0]), true
}

var varRef = regexp.MustCompile(`\$(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`)

// Expand substitutes $name / ${name} references using known top-level scalar
// variables. Unknown references are left as-is.
func (p *Package) Expand(s string) string {
	for range 5 {
		if !strings.Contains(s, "$") {
			break
		}
		out := varRef.ReplaceAllStringFunc(s, func(m string) string {
			name := strings.Trim(m[1:], "{}")
			if v, ok := p.Vars[name]; ok && !v.Array && len(v.Values) == 1 {
				return v.Values[0]
			}
			return m
		})
		if out == s {
			break
		}
		s = out
	}
	return s
}

// installFiles returns the scriptlet filenames referenced by install= or
// declared per split package, deduplicated.
func (p *Package) installFiles() []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		// An install scriptlet must be a plain file in the package directory.
		// Reject "."/".."; any path separator; and anything whose basename
		// differs from itself (parent traversal, absolute paths) so a hostile
		// install= value cannot steer pkglint into reading files outside the
		// package (traversal) or an unbounded device like /dev/zero (DoS).
		if name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	if v, ok := p.Vars["install"]; ok {
		for _, val := range v.Values {
			add(p.Expand(val))
		}
	}
	if p.SrcInfo != nil {
		for _, val := range p.SrcInfo.All("install") {
			add(val)
		}
	}
	return out
}

// Units returns the PKGBUILD followed by any parsed scriptlets.
func (p *Package) Units() []Unit {
	return append([]Unit{p.PKGBUILD}, p.Scriptlets...)
}

var suppressRe = regexp.MustCompile(`#\s*pkglint:\s*ignore=([A-Z0-9, ]+)`)

func parseSuppressions(raw []byte) map[int]map[string]bool {
	out := map[int]map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		m := suppressRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ids := map[string]bool{}
		for _, id := range strings.Split(m[1], ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids[id] = true
			}
		}
		out[i+1] = ids
	}
	return out
}

// Suppressed reports whether ruleID is suppressed at path:line by a directive
// on that line or the line above it, within the same file. A directive in one
// file never suppresses findings in another.
func (p *Package) Suppressed(ruleID, path string, line int) bool {
	perLine, ok := p.Suppressions[path]
	if !ok {
		return false
	}
	for _, l := range []int{line, line - 1} {
		if ids, ok := perLine[l]; ok && ids[ruleID] {
			return true
		}
	}
	return false
}

// RenderWord returns an approximate textual form of a word. dynamic is true
// when the word contains constructs whose value cannot be determined
// statically (command substitution, process substitution, arithmetic,
// indirection, or parameter operations). Plain references to unknown
// variables render as "$name" and are not considered dynamic, so prefix
// checks like `$pkgdir/...` still work. vars, when non-nil, resolves simple
// parameter references.
func RenderWord(w *syntax.Word, vars map[string]string) (s string, dynamic bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	dyn := renderParts(&b, w.Parts, vars)
	return b.String(), dyn
}

func renderParts(b *strings.Builder, parts []syntax.WordPart, vars map[string]string) bool {
	dynamic := false
	for _, part := range parts {
		switch x := part.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			if renderParts(b, x.Parts, vars) {
				dynamic = true
			}
		case *syntax.ParamExp:
			if x.Excl || x.Length || x.Width || x.Index != nil || x.Slice != nil || x.Repl != nil || x.Exp != nil || x.Names != 0 {
				b.WriteString("\x00")
				dynamic = true
				break
			}
			if vars != nil {
				if v, ok := vars[x.Param.Value]; ok {
					b.WriteString(v)
					break
				}
			}
			b.WriteString("$" + x.Param.Value)
		default:
			b.WriteString("\x00")
			dynamic = true
		}
	}
	return dynamic
}
