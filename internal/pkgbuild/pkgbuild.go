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

// Package is a fully loaded package directory.
type Package struct {
	Dir        string
	PKGBUILD   Unit
	Scriptlets []Unit
	Vars       map[string]*Var
	SrcInfo    *SrcInfo // nil when no .SRCINFO is present

	// Suppressions maps line number -> rule IDs disabled on that line via
	// "# pkglint: ignore=PB123[,PB456]" (applies to the same and next line).
	Suppressions map[int]map[string]bool
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
		Dir:          dir,
		PKGBUILD:     unit,
		Vars:         map[string]*Var{},
		Suppressions: parseSuppressions(raw),
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
		su, err := parseUnit(p, data, true)
		if err != nil {
			continue
		}
		pkg.Scriptlets = append(pkg.Scriptlets, su)
		for line, ids := range parseSuppressions(data) {
			pkg.Suppressions[line] = ids // best effort; line collisions across files are acceptable
		}
	}
	return pkg, nil
}

func parseUnit(path string, raw []byte, scriptlet bool) (Unit, error) {
	f, err := newParser().Parse(bytes.NewReader(raw), path)
	if err != nil {
		return Unit{}, fmt.Errorf("parse %s: %w", path, err)
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

// Suppressed reports whether ruleID is suppressed at the given line by a
// directive on that line or the line above it.
func (p *Package) Suppressed(ruleID string, line int) bool {
	for _, l := range []int{line, line - 1} {
		if ids, ok := p.Suppressions[l]; ok && ids[ruleID] {
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
