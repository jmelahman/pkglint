package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// PB6xx: PKGBUILD / .SRCINFO consistency. AUR helpers show users .SRCINFO
// metadata while makepkg executes the PKGBUILD — when the two disagree, the
// user reviewed something other than what runs.
var consistencyRules = []Rule{
	{
		ID:   "PB601",
		Name: "srcinfo-mismatch",
		Doc: ".SRCINFO is what the AUR web interface and helpers display; the PKGBUILD is what " +
			"executes. A mismatch means reviewers saw different metadata than the build uses — " +
			"sometimes a stale regeneration, sometimes deliberate misdirection.",
		Check: checkSrcInfoMatch,
	},
	{
		ID:   "PB602",
		Name: "network-in-pkgver",
		Doc: "pkgver() should derive a version from the already-fetched sources (git describe, " +
			"cat VERSION). Downloading inside pkgver() executes network-dependent code on every " +
			"makepkg invocation, including ones the user thought were offline.",
		Check: checkPkgverNetwork,
	},
}

func checkSrcInfoMatch(ctx *Context) []Finding {
	si := ctx.Pkg.SrcInfo
	if si == nil {
		return nil
	}
	var out []Finding
	pos := ctx.Pkg.PKGBUILD.File.Pos()
	mismatch := func(field, pkgVal, siVal string) {
		out = append(out, findingAt("PB601", Warn, ctx.Pkg.PKGBUILD.Path, pos,
			"%s differs between PKGBUILD (%q) and .SRCINFO (%q); regenerate .SRCINFO", field, pkgVal, siVal))
	}

	_, hasPkgverFn := ctx.Pkg.PKGBUILD.Functions["pkgver"]
	if !hasPkgverFn { // VCS packages update pkgver dynamically; drift is expected
		if v, ok := ctx.Pkg.Scalar("pkgver"); ok {
			if sv, ok := si.Get("pkgver"); ok && sv != v {
				mismatch("pkgver", v, sv)
			}
		}
		if v, ok := ctx.Pkg.Scalar("pkgrel"); ok {
			if sv, ok := si.Get("pkgrel"); ok && sv != v {
				mismatch("pkgrel", v, sv)
			}
		}
	}
	if v, ok := ctx.Pkg.Scalar("url"); ok && !strings.Contains(v, "$") {
		if sv, ok := si.Get("url"); ok && sv != v {
			mismatch("url", v, sv)
		}
	}

	var pkgbuildSources int
	for _, e := range ctx.Pkg.Sources() {
		_ = e
		pkgbuildSources++
	}
	var srcinfoSources int
	for key, vals := range si.Fields {
		if key == "source" || strings.HasPrefix(key, "source_") {
			srcinfoSources += len(vals)
		}
	}
	if srcinfoSources != pkgbuildSources && pkgbuildSources > 0 {
		mismatch("source count", strconv.Itoa(pkgbuildSources), fmt.Sprint(srcinfoSources))
	}
	return out
}

func checkPkgverNetwork(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if c.Fn != "pkgver" || c.Unit.Scriptlet {
			continue
		}
		fetches, ok := networkCommands[c.Name]
		if !ok || !fetches(c) {
			continue
		}
		out = append(out, c.finding("PB602", Warn,
			"%s accesses the network inside pkgver(); derive the version from fetched sources instead", c.Name))
	}
	return out
}
