package pkgbuild

import (
	"net/url"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SourceEntry is one element of a source=() array, parsed per makepkg's
// [filename::]url[#fragment][?query] convention.
type SourceEntry struct {
	Raw      string // as written
	Expanded string // with known variables substituted
	Filename string // explicit filename before ::, if any
	URL      string
	Proto    string            // full protocol, e.g. "git+https", "https", "" for local files
	VCS      string            // "git", "hg", "svn", "bzr", "fossil" or ""
	Fragment map[string]string // commit/tag/branch/revision -> value
	Query    string            // e.g. "signed"
	Local    bool
	Index    int
	Arch     string // "" for the plain source array, else e.g. "x86_64"
	Pos      syntax.Pos
}

var vcsProtos = map[string]bool{"git": true, "hg": true, "svn": true, "bzr": true, "fossil": true}

// Sources parses every source array (source, source_x86_64, ...) in the
// PKGBUILD.
func (p *Package) Sources() []SourceEntry {
	var out []SourceEntry
	for name, v := range p.Vars {
		if name != "source" && !strings.HasPrefix(name, "source_") {
			continue
		}
		arch := strings.TrimPrefix(strings.TrimPrefix(name, "source"), "_")
		for i, raw := range v.Values {
			e := parseSourceEntry(raw, p.Expand(raw))
			e.Index = i
			e.Arch = arch
			e.Pos = v.Pos
			out = append(out, e)
		}
	}
	return out
}

func parseSourceEntry(raw, expanded string) SourceEntry {
	e := SourceEntry{Raw: raw, Expanded: expanded, Fragment: map[string]string{}}
	rest := expanded

	if name, url, ok := strings.Cut(rest, "::"); ok {
		e.Filename = name
		rest = url
	}
	if u, q, ok := strings.Cut(rest, "?"); ok {
		// Fragments come before the query in makepkg URLs; handle both orders.
		e.Query = q
		rest = u
	}
	if u, frag, ok := strings.Cut(rest, "#"); ok {
		rest = u
		if k, v, ok := strings.Cut(frag, "="); ok {
			e.Fragment[k] = v
		}
	}
	e.URL = rest

	scheme, _, ok := strings.Cut(rest, "://")
	if !ok {
		e.Local = true
		return e
	}
	e.Proto = strings.ToLower(scheme)
	vcs, _, plus := strings.Cut(e.Proto, "+")
	if plus && vcsProtos[vcs] {
		e.VCS = vcs
	} else if vcsProtos[e.Proto] {
		e.VCS = e.Proto
	}
	return e
}

// Host returns the URL's hostname, when determinable.
func (e SourceEntry) Host() string {
	raw := e.URL
	if e.VCS != "" {
		if _, u, ok := strings.Cut(raw, "+"); ok {
			raw = u
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// checksum algorithms recognized by makepkg, weakest first.
var sumAlgos = []string{"ck", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "b2"}

// Checksums returns algo -> values for the sums arrays matching arch
// ("" for the base arrays).
func (p *Package) Checksums(arch string) map[string][]string {
	out := map[string][]string{}
	for _, algo := range sumAlgos {
		name := algo + "sums"
		if arch != "" {
			name += "_" + arch
		}
		if v, ok := p.Vars[name]; ok {
			out[algo] = v.Values
		}
	}
	return out
}

// SumsFor returns every checksum value across all algorithms for the source
// entry at the given index/arch.
func (p *Package) SumsFor(e SourceEntry) []string {
	var out []string
	for _, vals := range p.Checksums(e.Arch) {
		if e.Index < len(vals) {
			out = append(out, vals[e.Index])
		}
	}
	return out
}
