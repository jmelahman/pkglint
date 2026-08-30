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

	// LocalDigest hashes a source file that is *already* on disk, given the
	// package directory and the local filename makepkg gives the source. It
	// returns an error when the file is not there, and the fixer that needs it
	// then emits no edit and the finding stands.
	//
	// It never downloads. A digest cannot be derived from PKGBUILD text the
	// way a commit hash can be derived from a ref, so PB102's fix only repairs
	// packages whose sources have been fetched already — deliberately, since
	// fetching would mean pkglint issuing requests to URLs it read out of an
	// untrusted file. Implementations look in the package directory and
	// makepkg's source cache and nowhere else; the rules package does no file
	// I/O of its own.
	LocalDigest func(dir, filename string) (Digests, error)

	// ProbeHTTPS reports whether an https URL is actually served, returning nil
	// when it is and an error describing the refusal otherwise. It is nil when
	// probing is unavailable (offline), and a fixer that needs it then emits no
	// edit and the finding stands.
	//
	// It exists so the transport fixes can be checked rather than hoped: only
	// the server knows whether it answers on https, and PB104's rewrite is a
	// claim about the server. Implementations issue a headers-only request and
	// read no body — what comes back is used solely to decide whether the URL
	// resolves, never as input to anything. That distinction is what keeps this
	// inside pkglint's "never act on what the file says" line: the PKGBUILD
	// chooses an address to knock on, and nothing more.
	//
	// A successful probe means the URL exists over https, not that it serves
	// the same bytes. Nothing but the checksum can say that, which is why the
	// fix stays unsafe even when the probe passes.
	ProbeHTTPS func(url string) error
}

// Digests are hashes of one local source file, all computed from a single read
// so they provably describe the same bytes — which is what lets a fixer check
// a weak digest and emit a strong one for the same content. A field is empty
// when the implementation did not compute that algorithm.
type Digests struct {
	MD5    string
	SHA1   string
	SHA256 string
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
	for _, rule := range registry() {
		if rule.Fix == nil || rule.FixLevel == FixNone || rule.FixLevel > level || ignore[rule.ID] {
			continue
		}
		for _, e := range rule.Fix(ctx, env) {
			e.RuleID = rule.ID
			// e.Path is the unit the edit rewrites: usually the PKGBUILD, but
			// command-driven fixers also edit scriptlets. Check the directive in
			// that file, not a fixed one.
			if ctx.Pkg.Suppressed(rule.ID, e.Path, e.Line) {
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
	return applyByUnit(pkg, CollectEdits(NewContext(pkg), ignore, level, env))
}

// applyByUnit applies the edits to the units they address, returning one
// FixResult per unit that had edits.
func applyByUnit(pkg *pkgbuild.Package, edits []Edit) []FixResult {
	byPath := map[string][]Edit{}
	for _, e := range edits {
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
	// How many sources each written element expands to. A brace group that
	// yields several URLs shares one #fragment; resolving one URL's ref and
	// rewriting the shared text would pin every URL in the group to it.
	perElem := map[string]int{}
	for _, e := range ctx.Pkg.Sources() {
		perElem[elemKey(e.Arch, e.ElemIndex)]++
	}
	var edits []Edit
	for _, e := range ctx.Pkg.Sources() {
		if e.VCS != "git" {
			continue // only git refs are resolvable with `git ls-remote`
		}
		if perElem[elemKey(e.Arch, e.ElemIndex)] > 1 {
			continue
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
			if ctx.tracksTip(e.VCS) {
				continue // checkVCSPins does not flag it; pinning would freeze a -git package
			}
			fragKey, refVal = "branch", br
		} else {
			continue // no named ref to resolve into a commit deterministically
		}
		w := elems[elemKey(e.Arch, e.ElemIndex)]
		if w == nil {
			continue
		}
		if refVal == "" || strings.ContainsAny(refVal, "\x00$") {
			continue // the expanded ref is not statically known; nothing to resolve
		}
		raw := string(ctx.Pkg.PKGBUILD.Raw[off(w.Pos()):off(w.End())])
		// The written value may be the literal ref or spelled through a
		// variable (#tag=v$pkgver); either way the bytes from the key through
		// the end of the fragment value are what pin the ref, and the resolved
		// commit replaces them wholesale. Only a fragment whose *key* is hidden
		// inside a variable leaves nothing addressable to rewrite.
		key := "#" + fragKey + "="
		i := strings.Index(raw, key)
		if i < 0 {
			continue
		}
		j := i + len(key)
		for j < len(raw) && !strings.ContainsRune(`#?"'`, rune(raw[j])) {
			j++
		}
		sha, err := env.ResolveRef(e.URL, refVal)
		if err != nil || !commitHashRe.MatchString(sha) {
			continue
		}
		edits = append(edits, Edit{
			Path:  ctx.Pkg.PKGBUILD.Path,
			Start: off(w.Pos()),
			End:   off(w.End()),
			New:   raw[:i] + "#commit=" + sha + raw[j:],
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

// sourceElems maps each written source-array element to its AST word, keyed by
// arch and SourceEntry.ElemIndex so a finding can be matched back to the text
// it is about.
//
// Numbering must mirror how Package merges assignments, since that is what
// ElemIndex counts: `source+=(...)` continues the preceding array's numbering,
// while a plain `source=(...)` replaces the array and restarts at zero, exactly
// as in bash. Keying each assignment's elements from zero instead made every
// `+=` shadow the base array — usually losing the fix, and, when both entries
// carried the same `#ref` text, computing an edit for one element and writing
// it over another's byte range.
func sourceElems(u *pkgbuild.Unit) map[string]*syntax.Word {
	out := map[string]*syntax.Word{}
	next := map[string]int{}
	record := func(as *syntax.Assign) {
		if as == nil || as.Name == nil {
			return
		}
		name := as.Name.Value
		if name != "source" && !strings.HasPrefix(name, "source_") {
			return
		}
		arch := strings.TrimPrefix(strings.TrimPrefix(name, "source"), "_")
		if as.Index != nil {
			// `source[i]=url` updates one element in place — no reset, no new
			// element — mirroring Package.recordIndexed. Remap the element only
			// for a literal index; extend the numbering when the write lands
			// past the end, as the merged Values then do.
			if idx, ok := pkgbuild.AssignIndex(as); ok {
				if !as.Append {
					out[elemKey(arch, idx)] = as.Value
				}
				if idx >= next[arch] {
					next[arch] = idx + 1
				}
			}
			return
		}
		if !as.Append {
			for i := range next[arch] {
				delete(out, elemKey(arch, i))
			}
			next[arch] = 0
		}
		switch {
		case as.Array != nil:
			for _, el := range as.Array.Elems {
				out[elemKey(arch, next[arch])] = el.Value
				next[arch]++
			}
		case as.Value != nil:
			// A scalar assignment merges in as one value with no element of
			// its own. Consume the index so later elements stay aligned; the
			// missing key just means no edit, rather than a misdirected one.
			next[arch]++
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

// --- PB104/PB112: upgrade an insecure source transport to https ------------

// httpsProto returns the encrypted spelling of an unencrypted source protocol,
// and reports whether one exists that a probe can actually vouch for.
//
// http gains a "s"; ftp becomes https, since a host still publishing over ftp
// almost always serves the same tree over https (ftp.gnu.org and the kernel
// mirrors are the common cases) and makepkg has no encrypted ftp agent to
// switch to. A bare git:// URL — the unauthenticated git wire protocol — is
// rewritten to git+https://, which every forge that speaks git:// also serves
// at the same path, and git+http:// likewise moves to git+https://.
//
// svn:// and rsync:// are deliberately absent: svn+https:// depends on the
// server exposing a DAV endpoint that svn:// says nothing about, and rsync has
// no encrypted spelling of its own at all. There is no rewrite that is even
// usually right, so those findings stand. hg+http and svn+http are absent for
// a different reason: the spelling is obvious, but neither capability in
// FixEnv can check it — ProbeHTTPS speaks plain https and ResolveRef speaks
// git — and an offer the probe cannot vet would be an unverified rewrite.
func httpsProto(proto string) (string, bool) {
	switch proto {
	case "http", "ftp":
		return "https", true
	case "git", "git+http":
		return "git+https", true
	}
	return "", false
}

func fixInsecureTransport(ctx *Context, env *FixEnv) []Edit {
	return insecureTransportEdits(ctx, env, false)
}

func fixInsecureSignatureTransport(ctx *Context, env *FixEnv) []Edit {
	return insecureTransportEdits(ctx, env, true)
}

// probeTarget is the URL the rewritten source would be fetched from, and
// whether it could be determined at all.
//
// It is the expanded URL with its scheme replaced, minus the `filename::`
// prefix makepkg strips before fetching. A VCS source loses the makepkg
// fragment and query too — `#commit=…` and `?signed` address makepkg, not the
// remote — while a plain download keeps its query string, which belongs to the
// server and often decides what it sends back.
//
// A URL still holding an unexpanded variable has no determinable target: the
// bytes on the line are not the address anything would be fetched from, so
// there is nothing a probe could confirm and the fix declines.
func probeTarget(e pkgbuild.SourceEntry, proto string) (string, bool) {
	raw := e.Expanded
	if e.Filename != "" {
		if _, rest, ok := strings.Cut(raw, "::"); ok {
			raw = rest
		}
	}
	if e.VCS != "" {
		raw = e.URL // fragment and query already stripped
	}
	old := e.Proto + "://"
	if len(raw) < len(old) || !strings.EqualFold(raw[:len(old)], old) {
		return "", false
	}
	rest := raw[len(old):]
	if rest == "" || strings.ContainsAny(rest, "$\x00") {
		return "", false
	}
	return proto + "://" + rest, true
}

// httpsServed reports whether the rewritten URL is really served, asking the
// protocol's own client: a git remote answers `git ls-remote` or it is not a
// git remote, and everything else is an HTTP endpoint a headers-only request
// can reach. Without the capability to ask — offline — it answers false, so
// the fix never fires on an assumption.
func httpsServed(env *FixEnv, e pkgbuild.SourceEntry, url string) bool {
	if e.VCS == "git" {
		if env.ResolveRef == nil {
			return false
		}
		// Any ref would do; HEAD is the one every remote has, so this asks
		// "does a git repository answer here" and nothing more.
		_, err := env.ResolveRef(url, "HEAD")
		return err == nil
	}
	if env.ProbeHTTPS == nil {
		return false
	}
	return env.ProbeHTTPS(url) == nil
}

// insecureTransportEdits rewrites the scheme of every insecurely fetched
// source. The tier split mirrors the checks': the PB104 fixer claims a written
// element holding an ordinary source, the PB112 fixer one holding a signature,
// so each rule fixes what it reports. A brace element carrying both
// (`foo{,.sig}`) is claimed by each; their identical edits collapse when
// applied.
//
// Every rewrite is checked against the server first: the edit is a claim that
// the host serves this path over https, which is not a claim a PKGBUILD can
// settle, and an unverified rewrite trades a compromisable build for a broken
// one. One written element can expand to several sources sharing the one
// written scheme, and the single edit re-addresses all of them — so all of
// them must verify, the other rule's included. A probe that fails, or a probe
// that cannot be made at all, for any URL the element expands to, leaves the
// finding standing for a maintainer to resolve.
//
// It stays an unsafe fix even so. A reachable URL is not the same URL: the
// probe establishes that something answers over https, never that it answers
// with the bytes the http fetch would have returned. For a source pinned to a
// strong digest, makepkg catches the difference on the next build; for a SKIP
// or a VCS clone, only a human does. That gap is exactly the review
// --unsafe-fix asks for.
//
// The digests are left alone: https fetches the same artifact, so a sums array
// that verified the http download verifies the https one. If it does not, the
// bytes differed, and that is precisely what the checksum is there to catch.
func insecureTransportEdits(ctx *Context, env *FixEnv, signatures bool) []Edit {
	if env == nil {
		return nil
	}
	// Group the entries by the written element they expand from: the element
	// is the unit of rewriting, however many sources it becomes.
	var order []string
	groups := map[string][]pkgbuild.SourceEntry{}
	for _, e := range ctx.Pkg.Sources() {
		if e.Local {
			continue
		}
		k := elemKey(e.Arch, e.ElemIndex)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], e)
	}
	elems := sourceElems(&ctx.Pkg.PKGBUILD)
	var edits []Edit
	seen := map[int]bool{}
	for _, k := range order {
		entries := groups[k]
		claimed := false
		for _, e := range entries {
			claimed = claimed || isSignatureSource(e) == signatures
		}
		e0 := entries[0]
		if !claimed {
			continue
		}
		if _, insecure := insecureProto(e0); !insecure {
			continue
		}
		proto, ok := httpsProto(e0.Proto)
		if !ok {
			continue
		}
		w := elems[k]
		if w == nil {
			continue
		}
		raw := string(ctx.Pkg.PKGBUILD.Raw[off(w.Pos()):off(w.End())])
		old := e0.Proto + "://"
		i := strings.Index(raw, old)
		// The scheme has to be written out literally and exactly once. Spelled
		// through a variable ("$_proto://…") there is nothing to rewrite, and
		// appearing twice — a proxy URL carrying another URL in its query, say
		// — leaves no way to tell which occurrence is the transport.
		if i < 0 || strings.Contains(raw[i+1:], old) {
			continue
		}
		at := off(w.Pos()) + i
		if seen[at] {
			continue
		}
		// Each distinct URL the element expands to is probed once, and one
		// refusal vetoes the whole element: the rewrite would re-address that
		// URL too, on nothing but hope.
		var targets []string
		probed := map[string]bool{}
		served := true
		for _, e := range entries {
			target, ok := probeTarget(e, proto)
			if !ok || e.Proto != e0.Proto {
				served = false
				break
			}
			if probed[target] {
				continue
			}
			probed[target] = true
			if !httpsServed(env, e, target) {
				served = false
				break
			}
			targets = append(targets, target)
		}
		if !served {
			continue
		}
		seen[at] = true
		edits = append(edits, Edit{
			Path:  ctx.Pkg.PKGBUILD.Path,
			Start: at,
			End:   at + len(old),
			New:   proto + "://",
			Line:  int(e0.Pos.Line()),
			Desc:  fmt.Sprintf("fetch over %s:// instead of %s:// (%s answers)", proto, e0.Proto, strings.Join(targets, ", ")),
		})
	}
	return edits
}

// --- PB102: add a strong digest beside a weak one --------------------------

// fixWeakChecksums writes a sha256sums array next to a weak md5sums/sha1sums,
// but only when it can show the bytes it hashed are the bytes the weak digest
// already vouched for.
//
// This fix is unlike every other one here: the value to write is data, not
// syntax, and no amount of reading the PKGBUILD recovers it. env.LocalDigest
// supplies it from sources already fetched, so a package whose sources have
// never been downloaded simply keeps the finding — see LocalDigest's comment
// for why pkglint will not fetch them to close it.
//
// What makes the result trustworthy rather than merely plausible is that the
// weak digest is re-computed from the very same read as the sha256 and must
// match. The sha256 written therefore describes bytes the existing chain
// already covered: substituting them needs an md5 *preimage*, not the
// collision that makes md5 unfit for new use. Without that check the fix would
// just be laundering whatever happens to sit in the cache into an
// authoritative-looking digest. A mismatch — upstream silently re-rolled the
// tarball, or something worse — abandons the array rather than certifying it.
//
// Arrays are all-or-nothing per arch. makepkg pairs sums to sources by index,
// so an array with a gap in it is not a partial fix but a misaligned one.
func fixWeakChecksums(ctx *Context, env *FixEnv) []Edit {
	if env == nil || env.LocalDigest == nil {
		return nil
	}
	var edits []Edit
	for _, arch := range ctx.archesWithSums() {
		if e, ok := strongSumsEdit(ctx, env, arch); ok {
			edits = append(edits, e)
		}
	}
	return edits
}

// strongSumsEdit builds the one sha256sums array for arch, or reports that it
// could not. Both weak arrays being present (md5sums *and* sha1sums) still
// yields a single edit, since one strong array is what clears the finding.
func strongSumsEdit(ctx *Context, env *FixEnv, arch string) (Edit, bool) {
	sums := ctx.Pkg.Checksums(arch)
	if hasStrongSum(sums) {
		return Edit{}, false // PB102 is silent here; nothing to fix
	}
	witness, v := weakSumsVar(ctx, sums, arch)
	if v == nil {
		return Edit{}, false
	}
	vals := sums[witness.algo]
	// One plain array assignment holding exactly these values: the array the
	// edit writes has to pair index-for-index with what makepkg pairs, and a
	// count arrived at through `+=` merges or brace groups is a count this
	// fixer cannot reproduce by writing elements out one per line. Those are
	// left to updpkgsums.
	if v.CountUnknown || v.Assign == nil || v.Assign.Array == nil ||
		len(v.Assign.Array.Elems) != len(v.Values) || len(vals) != len(v.Values) {
		return Edit{}, false
	}
	srcs := sourcesForArch(ctx, arch)
	if len(srcs) != len(vals) {
		return Edit{}, false // PB110's territory; pairing here would misalign
	}
	strong := make([]string, len(vals))
	hashed := 0
	for i, e := range srcs {
		s, ok := strongSumValue(ctx, env, e, witness, vals[i])
		if !ok {
			return Edit{}, false
		}
		if !isSkip(s) {
			hashed++
		}
		strong[i] = s
	}
	// An all-SKIP array would satisfy the rule's "a strong digest is present"
	// test while verifying nothing — silencing PB102 instead of fixing it.
	if hashed == 0 {
		return Edit{}, false
	}
	raw := ctx.Pkg.PKGBUILD.Raw
	// Insert on the line after the weak array ends, past any trailing comment
	// on its closing line.
	at := off(v.Assign.End())
	for at < len(raw) && raw[at] != '\n' {
		at++
	}
	return Edit{
		Path:  ctx.Pkg.PKGBUILD.Path,
		Start: at,
		End:   at,
		New:   "\n" + sumsArrayText(sumsName("sha256", arch), strong),
		Line:  int(v.Pos.Line()),
		Desc: fmt.Sprintf("add %s (%d digest(s) hashed locally and checked against %s)",
			sumsName("sha256", arch), hashed, sumsName(witness.algo, arch)),
	}, true
}

// strongSumValue returns one source's sha256sums entry: SKIP where makepkg wants
// one, else the local file's hash — gated on the weak digest matching the same
// bytes.
func strongSumValue(ctx *Context, env *FixEnv, e pkgbuild.SourceEntry, witness weakWitness, weak string) (string, bool) {
	// A VCS source has no single file to hash and takes SKIP in every sums
	// array. So does an entry already written SKIP: that is a detached
	// signature doing the verifying, or an unverified source, and either way
	// PB101 and PB111 own it. Carrying the SKIP across keeps this fix from
	// quietly changing what is verified.
	if e.VCS != "" || isSkip(weak) {
		return "SKIP", true
	}
	d, err := env.LocalDigest(ctx.Pkg.Dir, effectiveFilename(e))
	if err != nil || d.SHA256 == "" {
		return "", false
	}
	if got := witness.of(d); got == "" || !strings.EqualFold(got, weak) {
		return "", false
	}
	return d.SHA256, true
}

// weakWitness is a weak digest the fixer can re-compute, and so can use to
// check that a local file is the one a PKGBUILD already describes.
type weakWitness struct {
	algo string
	of   func(Digests) string
}

// weakWitnesses are those digests, best first: sha1 is the stronger witness of
// the two. ck is deliberately absent — it is makepkg's CRC, which pkglint does
// not compute, so a ck-only package offers nothing to check the bytes against
// and gets no fix.
var weakWitnesses = []weakWitness{
	{"sha1", func(d Digests) string { return d.SHA1 }},
	{"md5", func(d Digests) string { return d.MD5 }},
}

// weakSumsVar picks the weak array to verify against, returning the witness
// and the Var holding it. A nil Var means there is nothing usable.
func weakSumsVar(ctx *Context, sums map[string][]string, arch string) (weakWitness, *pkgbuild.Var) {
	for _, w := range weakWitnesses {
		if !hasRealSum(sums[w.algo]) {
			continue
		}
		if v := ctx.Pkg.Vars[sumsName(w.algo, arch)]; v != nil {
			return w, v
		}
	}
	return weakWitness{}, nil
}

// sourcesForArch returns arch's sources in the index order makepkg pairs
// checksums by.
func sourcesForArch(ctx *Context, arch string) []pkgbuild.SourceEntry {
	var out []pkgbuild.SourceEntry
	for _, e := range ctx.Pkg.Sources() {
		if e.Arch == arch {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// sumsArrayText renders a sums array the way updpkgsums does: one value per
// line, aligned under the first, so a long array stays readable.
func sumsArrayText(name string, vals []string) string {
	var b strings.Builder
	b.WriteString(name + "=('" + vals[0] + "'")
	indent := strings.Repeat(" ", len(name)+2)
	for _, v := range vals[1:] {
		b.WriteString("\n" + indent + "'" + v + "'")
	}
	b.WriteString(")")
	return b.String()
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

// fixGoDownloads gives the build its modules ahead of time: a prepare() that
// runs `go mod download`, entered through the same cd the build step uses so
// it lands in the same module. That is the finding message's first remedy, it
// works for sources that ship no vendor directory (a git tag rarely does),
// and goVendored recognizes the download step, so the finding clears for the
// right reason. The old edit — appending -mod=vendor to the build line —
// looked cheaper but pointed at a vendor directory that usually does not
// exist, and a later -mod flag on the same line overrode it silently anyway.
func fixGoDownloads(ctx *Context, _ *FixEnv) []Edit {
	if goVendored(ctx) {
		return nil
	}
	for _, c := range ctx.CommandsNamed("go") {
		if !c.InBuildPhase() {
			continue
		}
		switch c.Subcommand() {
		case "build", "install", "test", "run":
		default:
			continue
		}
		// One structural edit fixes every flagged command in the file, so the
		// first one carries it.
		if edit, ok := goModDownloadEdit(ctx, c); ok {
			return []Edit{edit}
		}
		return nil
	}
	return nil
}

// goModDownloadEdit inserts `go mod download` into prepare() — extending the
// function if the PKGBUILD has one, writing a fresh one directly above c's
// function otherwise. The download gets -modcacherw (unless GOFLAGS already
// carries it) so the cache the fix creates stays removable, as PB916 asks.
func goModDownloadEdit(ctx *Context, c Command) (Edit, bool) {
	u := c.Unit
	indent := lineIndent(u.Raw, off(c.Stmt.Pos()))
	line := int(c.Stmt.Pos().Line())
	download := "go mod download -modcacherw\n"
	for _, v := range assignmentsTo(ctx, "GOFLAGS") {
		if strings.Contains(v, "-modcacherw") {
			download = "go mod download\n"
			break
		}
	}

	if fd := u.Functions["prepare"]; fd != nil {
		block, ok := fd.Body.Cmd.(*syntax.Block)
		if !ok {
			return Edit{}, false
		}
		at := lineStart(u.Raw, off(block.Rbrace))
		if at <= off(block.Lbrace) {
			return Edit{}, false // a one-line prepare(); nowhere to put a new line
		}
		var b strings.Builder
		// prepare() may do its work at $srcdir's root; without a cd of its
		// own the download must still land in the module the build compiles.
		if !fnHasCommand(ctx, u, "prepare", "cd") {
			b.WriteString(cdLine(ctx, u, c.Fn))
		}
		b.WriteString(indent + download)
		return Edit{
			Path: u.Path, Start: at, End: at, New: b.String(), Line: line,
			Desc: "add `go mod download` to prepare() so the build needn't fetch",
		}, true
	}

	fd := u.Functions[c.Fn]
	if fd == nil {
		return Edit{}, false
	}
	at := lineStart(u.Raw, off(fd.Pos()))
	var b strings.Builder
	b.WriteString("prepare() {\n")
	b.WriteString(cdLine(ctx, u, c.Fn))
	b.WriteString(indent + download)
	b.WriteString("}\n\n")
	return Edit{
		Path: u.Path, Start: at, End: at, New: b.String(), Line: line,
		Desc: "add prepare() with `go mod download` so " + c.Fn + "() needn't fetch",
	}, true
}

// cdLine returns fn's opening cd statement as a full source line — indent and
// any `|| exit` guard included — or "" when fn has none or its cd shares the
// line with another command. prepare() must land in the directory the build
// step runs in, and copying the exact line is how it provably does.
func cdLine(ctx *Context, u *pkgbuild.Unit, fn string) string {
	for _, c := range ctx.Commands() {
		if c.Unit != u || c.Fn != fn || c.Name != "cd" {
			continue
		}
		start := lineStart(u.Raw, off(c.Stmt.Pos()))
		end := off(c.Stmt.End())
		for end < len(u.Raw) && u.Raw[end] != '\n' {
			end++
		}
		line := string(u.Raw[start:end])
		rest := line[off(c.Stmt.End())-start:]
		if rest != "" && !cdGuardRe.MatchString(rest) {
			return ""
		}
		return line + "\n"
	}
	return ""
}

// cdGuardRe matches the failure guard a cd is allowed to share its line with.
var cdGuardRe = regexp.MustCompile(`^\s*\|\|\s*(exit|return)\b[^|&;]*$`)

func fnHasCommand(ctx *Context, u *pkgbuild.Unit, fn, name string) bool {
	for _, c := range ctx.Commands() {
		if c.Unit == u && c.Fn == fn && c.Name == name {
			return true
		}
	}
	return false
}

// lineStart returns the offset of the first byte of the line containing o.
func lineStart(raw []byte, o int) int {
	for o > 0 && raw[o-1] != '\n' {
		o--
	}
	return o
}

// lineIndent returns the leading whitespace of the line containing o.
func lineIndent(raw []byte, o int) string {
	start := lineStart(raw, o)
	end := start
	for end < len(raw) && (raw[end] == ' ' || raw[end] == '\t') {
		end++
	}
	return string(raw[start:end])
}

// --- PB914/PB915/PB916: Arch Go guideline build flags ------------------------

// goFlagInsertion returns the offset just after the go subcommand's verb word
// ("build", "install", or the verb after "mod"), where an inserted flag is
// still parsed as a flag: go's flag parsing stops at the first non-flag
// argument, so appending at the end of the call — what the cargo fix does —
// would hand the flag to the package loader instead.
func goFlagInsertion(c Command) (int, bool) {
	verb := c.Subcommand()
	if verb == "mod" {
		if verb = secondSubcommand(c); verb == "" {
			return 0, false
		}
	}
	w := wordByValue(c, verb)
	if w == nil {
		return 0, false
	}
	return off(w.End()), true
}

// goFlagEdits inserts flag into every command in cmds that neither passes it
// nor inherits it from a GOFLAGS assignment.
func goFlagEdits(ctx *Context, cmds []Command, flagPrefix, flag string) []Edit {
	goflags := assignmentsTo(ctx, "GOFLAGS")
	var edits []Edit
	for _, c := range cmds {
		if goFlagAddressed(goflags, c, flagPrefix) {
			continue
		}
		at, ok := goFlagInsertion(c)
		if !ok {
			continue
		}
		edits = append(edits, Edit{
			Path:  c.Unit.Path,
			Start: at,
			End:   at,
			New:   " " + flag,
			Line:  int(c.Stmt.Pos().Line()),
			Desc:  fmt.Sprintf("insert %s into `go %s`", flag, c.Subcommand()),
		})
	}
	return edits
}

func fixGoPIE(ctx *Context, _ *FixEnv) []Edit {
	return goFlagEdits(ctx, goBuildCommands(ctx), "-buildmode", "-buildmode=pie")
}

func fixGoTrimpath(ctx *Context, _ *FixEnv) []Edit {
	return goFlagEdits(ctx, goBuildCommands(ctx), "-trimpath", "-trimpath")
}

func fixGoModcacheRW(ctx *Context, _ *FixEnv) []Edit {
	return goFlagEdits(ctx, goModuleCommands(ctx), "-modcacherw", "-modcacherw")
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
