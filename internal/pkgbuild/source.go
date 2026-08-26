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

	// ElemIndex is the index of the written array element this entry came
	// from, counting across every assignment merged into the array. It
	// differs from Index whenever an element expands to more than one entry:
	// `foo{,.sig}` is two entries (Index 0 and 1) written as one element
	// (ElemIndex 0 for both). Use Index to pair with checksums, ElemIndex to
	// address the source text.
	ElemIndex int
}

var vcsProtos = map[string]bool{"git": true, "hg": true, "svn": true, "bzr": true, "fossil": true}

// Sources parses every source array (source, source_x86_64, ...) in the
// PKGBUILD. Brace groups expand to one entry each — `foo.tar.gz{,.sig}` is
// two sources to makepkg — and Index counts expanded entries, matching how
// makepkg pairs sources with checksums.
func (p *Package) Sources() []SourceEntry {
	var out []SourceEntry
	for name, v := range p.Vars {
		if name != "source" && !strings.HasPrefix(name, "source_") {
			continue
		}
		arch := strings.TrimPrefix(strings.TrimPrefix(name, "source"), "_")
		idx := 0
		for rawIdx, raw := range v.Values {
			// Each entry reports its own written element's position. Values
			// beyond Assign.Array.Elems (scalar-derived, or appended by a
			// `+=` assignment the merge did not keep an Assign for) fall back
			// to the array's own position.
			pos := v.Pos
			if v.Assign != nil && v.Assign.Array != nil && rawIdx < len(v.Assign.Array.Elems) {
				if el := v.Assign.Array.Elems[rawIdx]; el.Value != nil {
					pos = el.Value.Pos()
				}
			}
			for _, expanded := range expandBraces(p.Expand(raw)) {
				e := parseSourceEntry(raw, expanded)
				e.Index = idx
				e.ElemIndex = rawIdx
				e.Arch = arch
				e.Pos = pos
				out = append(out, e)
				idx++
			}
		}
	}
	return out
}

// expandBraces performs bash-style brace expansion for the simple {a,b,c}
// groups that appear in source arrays. ${var} parameter braces and groups
// without a comma (which bash leaves literal too) are skipped; nested groups
// are rare enough to leave as-is.
func expandBraces(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		if i > 0 && s[i-1] == '$' { // ${var}: not a brace group
			if j := strings.IndexByte(s[i:], '}'); j >= 0 {
				i += j
			}
			continue
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return []string{s}
		}
		j += i
		inner := s[i+1 : j]
		if strings.Contains(inner, "{") || !strings.Contains(inner, ",") {
			continue
		}
		var out []string
		for alt := range strings.SplitSeq(inner, ",") {
			out = append(out, expandBraces(s[:i]+alt+s[j+1:])...)
		}
		return out
	}
	return []string{s}
}

func parseSourceEntry(raw, expanded string) SourceEntry {
	e := SourceEntry{Raw: raw, Expanded: expanded, Fragment: map[string]string{}}
	rest := expanded

	if name, url, ok := strings.Cut(rest, "::"); ok {
		e.Filename = name
		rest = url
	}
	// URL ends at the first '#' (fragment) or '?' (query); makepkg allows
	// either order (…#frag?query or …?query#frag), so parse them positionally.
	tail := ""
	if i := strings.IndexAny(rest, "#?"); i >= 0 {
		tail = rest[i:]
		rest = rest[:i]
	}
	for tail != "" {
		delim := tail[0]
		seg := tail[1:]
		if j := strings.IndexAny(seg, "#?"); j >= 0 {
			tail = seg[j:]
			seg = seg[:j]
		} else {
			tail = ""
		}
		if delim == '#' {
			if k, v, ok := strings.Cut(seg, "="); ok {
				e.Fragment[k] = v
			}
		} else {
			e.Query = seg
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
