package rules

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Ecosystem predicates shared by the Arch package-guideline rules
// (guidelines.go, pystyle.go, ruststyle.go, buildsys.go, vcsstyle.go,
// naming.go). Nearly every guideline rule is conditional on the package being
// of a kind — named with a prefix, depending on a toolchain, invoking a build
// system — so the "is this that kind of package" questions live here, built on
// the same primitives the other rules already use (varElems, staticVal,
// depsFor), rather than being re-derived per rule.

// pkgnames returns the statically-known package names this PKGBUILD builds:
// every pkgname element whose value is resolvable without running the file.
func pkgnames(ctx *Context) []string {
	var out []string
	for _, e := range varElems(ctx.Pkg.Vars["pkgname"]) {
		if val, ok := staticVal(ctx.Pkg, e.Value); ok && val != "" {
			out = append(out, val)
		}
	}
	return out
}

// hasDep reports whether field (or a declared _$arch variant of it) names the
// package, ignoring version constraints.
func hasDep(ctx *Context, field, name string) bool {
	_, ok := depsFor(ctx, field)[name]
	return ok
}

// depEntry is one statically-known dependency-array element with its position,
// for rules that report on the entry itself.
type depEntry struct {
	Name string // version constraint and description stripped
	Full string // as written
	Pos  syntax.Pos
}

// depEntries yields the static entries of field and its declared _$arch
// variants. Unlike depsFor it keeps positions and duplicates, so findings can
// point at the entry rather than the array.
func depEntries(ctx *Context, field string) []depEntry {
	var out []depEntry
	names := []string{field}
	for _, a := range concreteArches(ctx) {
		names = append(names, field+"_"+a)
	}
	for _, n := range names {
		for _, e := range varElems(ctx.Pkg.Vars[n]) {
			if val, ok := staticVal(ctx.Pkg, e.Value); ok && val != "" {
				out = append(out, depEntry{Name: depName(val), Full: val, Pos: e.Pos})
			}
		}
	}
	return out
}

// pkgdirSubdir reports whether a rendered write target lands under
// $pkgdir<sub> (sub like "/usr/local"), tolerating the ${pkgdir} spelling.
func pkgdirSubdir(target, sub string) bool {
	t := strings.ReplaceAll(target, "${pkgdir}", "$pkgdir")
	return strings.HasPrefix(t, "$pkgdir"+sub)
}

// packagePhaseWrites yields every file-writing command in package() or a
// split package_*() function together with its destination arguments — the
// commands that decide where in $pkgdir the package's files land.
func packagePhaseWrites(ctx *Context) []struct {
	Cmd   Command
	Dests []string
} {
	var out []struct {
		Cmd   Command
		Dests []string
	}
	for _, c := range ctx.Commands() {
		if c.Fn != "package" && !strings.HasPrefix(c.Fn, "package_") {
			continue
		}
		if !fileWriters[c.Name] {
			continue
		}
		if dests := writeDests(c); len(dests) > 0 {
			out = append(out, struct {
				Cmd   Command
				Dests []string
			}{c, dests})
		}
	}
	return out
}
