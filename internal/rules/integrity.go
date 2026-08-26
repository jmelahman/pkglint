package rules

import (
	"os"
	"path/filepath"
	"strings"
)

// PB1xx: source integrity.
var integrityRules = []Rule{
	{
		ID:   "PB101",
		Name: "skipped-checksum",
		Doc: "Every remote, non-VCS source should carry a real checksum. `SKIP` means makepkg " +
			"performs no integrity verification at all: if the upstream file or the connection is " +
			"tampered with, nothing notices. Pin the artifact with a sha256 or stronger digest.",
		Check: checkSkippedChecksums,
	},
	{
		ID:   "PB102",
		Name: "weak-checksum",
		Doc: "md5 and sha1 are broken for collision resistance. When they are the only digests " +
			"present, an attacker able to produce collisions can substitute the source artifact. " +
			"Add sha256sums, sha512sums or b2sums.",
		Check: checkWeakChecksums,
	},
	{
		ID:   "PB103",
		Name: "unpinned-vcs-source",
		Doc: "A VCS source without `#commit=` pins to a mutable reference: branches move and tags " +
			"can be re-pointed by anyone with push access (or a compromised forge account). Pinning " +
			"the exact commit hash makes the fetched tree tamper-evident.",
		Check: checkVCSPins,
	},
	{
		ID:   "PB104",
		Name: "insecure-transport",
		Doc: "Sources fetched over http://, git:// or ftp:// can be modified in transit. With a " +
			"strong checksum this downgrades availability rather than integrity, but combined with " +
			"SKIP or weak sums it is a working man-in-the-middle vector. Use https:// (or git+https://).",
		Check: checkInsecureTransport,
	},
	{
		ID:   "PB105",
		Name: "source-url-mismatch",
		Doc: "A source hosted on a different domain than the project's `url` is worth a second " +
			"look: repackaged or 'mirrored' artifacts are a common way to slip in modified binaries. " +
			"Often legitimate (CDNs, release mirrors) — hence only informational.",
		Check: checkSourceDomains,
	},
	{
		ID:   "PB106",
		Name: "dlagents-override",
		Doc: "Overriding DLAGENTS replaces makepkg's download logic with arbitrary commands, which " +
			"run before any checksum is verified. Legitimate uses exist but are rare enough that " +
			"every override deserves review.",
		Check: checkDLAgents,
	},
	{
		ID:   "PB107",
		Name: "missing-install-script",
		Doc: "The PKGBUILD references an install scriptlet that is not present next to it, so its " +
			"contents cannot be reviewed or linted.",
		Check: checkMissingInstall,
	},
}

func isSkip(s string) bool { return strings.EqualFold(s, "SKIP") }

func checkSkippedChecksums(ctx *Context) []Finding {
	var out []Finding
	for _, e := range ctx.Pkg.Sources() {
		if e.VCS != "" || e.Local {
			continue
		}
		sums := ctx.Pkg.SumsFor(e)
		allSkip := true
		for _, s := range sums {
			if !isSkip(s) {
				allSkip = false
			}
		}
		if len(sums) == 0 || allSkip {
			out = append(out, findingAt("PB101", Error, ctx.Pkg.PKGBUILD.Path, e.Pos,
				"remote source %q has no checksum (SKIP): the download is never verified", e.Raw))
		}
	}
	return out
}

func checkWeakChecksums(ctx *Context) []Finding {
	var out []Finding
	for _, arch := range ctx.archesWithSums() {
		sums := ctx.Pkg.Checksums(arch)
		strong := len(sums["sha224"]) > 0 || len(sums["sha256"]) > 0 || len(sums["sha384"]) > 0 ||
			len(sums["sha512"]) > 0 || len(sums["b2"]) > 0
		if strong {
			continue
		}
		for _, algo := range []string{"ck", "md5", "sha1"} {
			real := false
			for _, s := range sums[algo] {
				if !isSkip(s) {
					real = true
				}
			}
			if real {
				name := algo + "sums"
				if arch != "" {
					name += "_" + arch
				}
				v := ctx.Pkg.Vars[name]
				out = append(out, findingAt("PB102", Warn, ctx.Pkg.PKGBUILD.Path, v.Pos,
					"%s is the strongest digest present; add sha256sums or b2sums", name))
			}
		}
	}
	return out
}

func (ctx *Context) archesWithSums() []string {
	seen := map[string]bool{"": true}
	out := []string{""}
	for name := range ctx.Pkg.Vars {
		for _, algo := range sumAlgoNames {
			if rest, ok := strings.CutPrefix(name, algo+"sums_"); ok && !seen[rest] {
				seen[rest] = true
				out = append(out, rest)
			}
		}
	}
	return out
}

var sumAlgoNames = []string{"ck", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "b2"}

func checkVCSPins(ctx *Context) []Finding {
	var out []Finding
	for _, e := range ctx.Pkg.Sources() {
		if e.VCS == "" {
			continue
		}
		if _, ok := e.Fragment["commit"]; ok {
			continue
		}
		if _, ok := e.Fragment["revision"]; ok { // svn/fossil
			continue
		}
		signed := strings.Contains(e.Query, "signed")
		if tag, ok := e.Fragment["tag"]; ok {
			if signed {
				continue // signed tag: verified against validpgpkeys
			}
			out = append(out, findingAt("PB103", Warn, ctx.Pkg.PKGBUILD.Path, e.Pos,
				"VCS source pinned to mutable tag %q; tags can be re-pointed — pin with #commit=", tag))
			continue
		}
		ref := "default branch"
		if b, ok := e.Fragment["branch"]; ok {
			ref = "branch " + b
		}
		out = append(out, findingAt("PB103", Warn, ctx.Pkg.PKGBUILD.Path, e.Pos,
			"VCS source follows %s with no #commit= pin; the fetched tree is not tamper-evident", ref))
	}
	return out
}

func checkInsecureTransport(ctx *Context) []Finding {
	var out []Finding
	for _, e := range ctx.Pkg.Sources() {
		if e.Local {
			continue
		}
		proto := e.Proto
		if _, rest, ok := strings.Cut(proto, "+"); ok {
			proto = rest
		}
		switch proto {
		case "http", "ftp", "git", "svn", "rsync":
			out = append(out, findingAt("PB104", Error, ctx.Pkg.PKGBUILD.Path, e.Pos,
				"source %q is fetched over unencrypted %s://", e.Raw, proto))
		}
	}
	return out
}

// domainPairs holds host suffix pairs that commonly belong to the same
// project despite different registrable domains.
var domainPairs = [][2]string{
	{"github.com", "githubusercontent.com"},
	{"github.com", "github.io"},
	{"gitlab.com", "gitlab.io"},
	{"pypi.org", "pythonhosted.org"},
	{"sourceforge.net", "sourceforge.io"},
}

var wellKnownHosts = []string{
	"files.pythonhosted.org", "registry.npmjs.org", "crates.io", "static.crates.io",
	"downloads.sourceforge.net", "ftp.gnu.org", "gitlab.freedesktop.org", "proxy.golang.org",
}

func checkSourceDomains(ctx *Context) []Finding {
	urlVal, ok := ctx.Pkg.Scalar("url")
	if !ok {
		return nil
	}
	urlHost := hostOf(urlVal)
	if urlHost == "" {
		return nil
	}
	var out []Finding
	for _, e := range ctx.Pkg.Sources() {
		h := e.Host()
		if h == "" || sameSite(h, urlHost) {
			continue
		}
		known := false
		for _, k := range wellKnownHosts {
			if h == k {
				known = true
			}
		}
		if known {
			continue
		}
		out = append(out, findingAt("PB105", Info, ctx.Pkg.PKGBUILD.Path, e.Pos,
			"source host %q differs from project url host %q", h, urlHost))
	}
	return out
}

func hostOf(rawurl string) string {
	_, rest, ok := strings.Cut(rawurl, "://")
	if !ok {
		return ""
	}
	host := rest
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndexByte(host, '@'); i >= 0 {
		host = host[i+1:]
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(host)
}

// sameSite is a naive registrable-domain comparison plus an allowlist of
// related host pairs.
func sameSite(a, b string) bool {
	site := func(h string) string {
		parts := strings.Split(h, ".")
		if len(parts) <= 2 {
			return h
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	sa, sb := site(a), site(b)
	if sa == sb {
		return true
	}
	for _, pair := range domainPairs {
		if (sa == pair[0] && sb == pair[1]) || (sa == pair[1] && sb == pair[0]) {
			return true
		}
	}
	return false
}

func checkDLAgents(ctx *Context) []Finding {
	if v, ok := ctx.Pkg.Vars["DLAGENTS"]; ok {
		return []Finding{findingAt("PB106", Warn, ctx.Pkg.PKGBUILD.Path, v.Pos,
			"DLAGENTS override replaces makepkg's download logic with custom commands")}
	}
	return nil
}

func checkMissingInstall(ctx *Context) []Finding {
	v, ok := ctx.Pkg.Vars["install"]
	if !ok {
		return nil
	}
	var out []Finding
	for _, val := range v.Values {
		name := ctx.Pkg.Expand(val)
		if name == "" || strings.ContainsAny(name, "$\x00") {
			continue
		}
		if _, err := os.Stat(filepath.Join(ctx.Pkg.Dir, name)); err != nil {
			out = append(out, findingAt("PB107", Warn, ctx.Pkg.PKGBUILD.Path, v.Pos,
				"install scriptlet %q referenced but not found next to the PKGBUILD", name))
		}
	}
	return out
}
