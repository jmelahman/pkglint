package rules

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func basename(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func hasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// hasVarRef reports whether a rendered word still contains an unresolved
// variable or dynamic marker.
func hasVarRef(s string) bool {
	return strings.ContainsAny(s, "$\x00")
}

var assignWordRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func isAssignWord(s string) bool { return assignWordRe.MatchString(s) }

// flattenPipe returns the statements of a pipeline in order, or nil when
// stmt is not a pipeline.
func flattenPipe(stmt *syntax.Stmt) []*syntax.Stmt {
	bc, ok := stmt.Cmd.(*syntax.BinaryCmd)
	if !ok || (bc.Op != syntax.Pipe && bc.Op != syntax.PipeAll) {
		return nil
	}
	var out []*syntax.Stmt
	var flatten func(s *syntax.Stmt)
	flatten = func(s *syntax.Stmt) {
		if b, ok := s.Cmd.(*syntax.BinaryCmd); ok && (b.Op == syntax.Pipe || b.Op == syntax.PipeAll) {
			flatten(b.X)
			flatten(b.Y)
			return
		}
		out = append(out, s)
	}
	flatten(stmt)
	return out
}

// pipelines yields every pipeline in a unit.
func pipelines(u *syntax.File) [][]*syntax.Stmt {
	var out [][]*syntax.Stmt
	seen := map[*syntax.Stmt]bool{}
	syntax.Walk(u, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok || seen[stmt] {
			return true
		}
		if segs := flattenPipe(stmt); segs != nil {
			out = append(out, segs)
			for _, s := range segs {
				seen[s] = true // don't re-report inner segments of the same pipe
			}
		}
		return true
	})
	return out
}

// stmtCommandName resolves the command name of a pipeline segment,
// unwrapping simple wrappers like sudo or env.
func stmtCommandName(stmt *syntax.Stmt, vars map[string]string) string {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return ""
	}
	c := (&Context{vars: vars}).newCommand(nil, "", stmt, call)
	return c.Name
}

// wordContainsCommand reports whether the word embeds a command substitution
// (or process substitution) that invokes one of names.
func wordContainsCommand(w *syntax.Word, names map[string]bool) bool {
	found := false
	syntax.Walk(w, func(node syntax.Node) bool {
		var stmts []*syntax.Stmt
		switch x := node.(type) {
		case *syntax.CmdSubst:
			stmts = x.Stmts
		case *syntax.ProcSubst:
			stmts = x.Stmts
		default:
			return true
		}
		for _, s := range stmts {
			syntax.Walk(s, func(n syntax.Node) bool {
				if call, ok := n.(*syntax.CallExpr); ok && len(call.Args) > 0 {
					name, _ := renderPlain(call.Args[0])
					if names[basename(name)] {
						found = true
					}
				}
				return !found
			})
		}
		return !found
	})
	return found
}

// renderPlain renders a word without variable resolution.
func renderPlain(w *syntax.Word) (string, bool) {
	var b strings.Builder
	dyn := false
	for _, part := range w.Parts {
		switch x := part.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, p := range x.Parts {
				if lit, ok := p.(*syntax.Lit); ok {
					b.WriteString(lit.Value)
				} else {
					dyn = true
				}
			}
		default:
			dyn = true
		}
	}
	return b.String(), dyn
}
