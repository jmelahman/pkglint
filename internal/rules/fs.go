package rules

import (
	"regexp"
	"strings"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

// PB4xx: filesystem and privilege hygiene.
var fsRules = []Rule{
	{
		ID:   "PB401",
		Name: "write-outside-builddir",
		Doc: "A build must only write beneath $srcdir and $pkgdir. Writes to $HOME or absolute " +
			"system paths either corrupt the builder's machine or hint at persistence being " +
			"installed outside the package manager's tracking.",
		Check: checkWritesOutside,
	},
	{
		ID:   "PB402",
		Name: "privilege-escalation",
		Doc: "makepkg builds must never escalate: sudo/su/doas/pkexec in a PKGBUILD runs arbitrary " +
			"commands as root on the build machine. Anything needing privileges belongs in the " +
			"package's install step, executed and tracked by pacman.",
		Check: checkPrivilegeEscalation,
	},
	{
		ID:   "PB403",
		Name: "setuid-file",
		Doc: "chmod u+s/g+s (or 4xxx/2xxx modes), and `install -m` with such a mode, create " +
			"setuid/setgid binaries — a privilege boundary that deserves explicit review whenever a " +
			"package ships one.",
		Check:    checkSetuid,
		FixLevel: FixUnsafe,
		Fix:      fixSetuid,
	},
	{
		ID:   "PB404",
		Name: "install-without-destdir",
		Doc: "A build system's install step in package() must be redirected into $pkgdir (via " +
			"DESTDIR, --root, --prefix, or --destdir). Without it, `make install` and friends write " +
			"into the builder's live filesystem instead of the staging directory — untracked by pacman " +
			"and often run with escalated privileges.",
		Check: checkInstallDestdir,
	},
	{
		ID:   "PB405",
		Name: "sensitive-file-write",
		Doc: "Writing to pacman's configuration (SigLevel/repos control package trust), the dynamic " +
			"linker's preload/search config, or sudoers — or running pacman-key — reconfigures the " +
			"system's trust and privilege boundaries. In a PKGBUILD or scriptlet this is a persistence " +
			"and privilege-escalation vector.",
		Check: checkSensitiveWrites,
	},
}

// prefixes always acceptable as write targets.
var allowedWritePrefixes = []string{
	"$pkgdir", "${pkgdir", "$srcdir", "${srcdir", "$startdir", "${startdir",
	"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/fd/",
	"/tmp/", "$TMPDIR", "${TMPDIR",
}

// fileWriters are commands whose arguments name files they create or modify.
var fileWriters = map[string]bool{
	"cp": true, "mv": true, "install": true, "ln": true, "tee": true,
	"mkdir": true, "touch": true, "rm": true, "rmdir": true, "dd": true,
}

func writeTargetViolation(target string) string {
	t := strings.TrimSpace(target)
	if t == "" || strings.Contains(t, "\x00") {
		return ""
	}
	if sensitiveWritePath(t) != "" {
		return "" // reported by PB405 instead, to avoid a duplicate finding
	}
	for _, p := range allowedWritePrefixes {
		if strings.HasPrefix(t, p) {
			return ""
		}
	}
	if strings.HasPrefix(t, "$HOME") || strings.HasPrefix(t, "${HOME") || strings.HasPrefix(t, "~/") {
		return "writes into the user's home directory"
	}
	if strings.HasPrefix(t, "/") {
		return "writes to an absolute system path"
	}
	return ""
}

func checkWritesOutside(ctx *Context) []Finding {
	var out []Finding
	units := ctx.Pkg.Units()
	for i := range units {
		u := &units[i]
		syntax.Walk(u.File, func(node syntax.Node) bool {
			r, ok := node.(*syntax.Redirect)
			if !ok || r.Word == nil {
				return true
			}
			switch r.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
			default:
				return true
			}
			target, _ := pkgbuild.RenderWord(r.Word, ctx.vars)
			if why := writeTargetViolation(target); why != "" {
				out = append(out, findingAt("PB401", Error, u.Path, r.Pos(),
					"redirection to %q %s", target, why))
			}
			return true
		})
	}

	for _, c := range ctx.Commands() {
		if !fileWriters[c.Name] {
			continue
		}
		for _, target := range writeDests(c) {
			if why := writeTargetViolation(target); why != "" {
				out = append(out, c.finding("PB401", Error, "%s %s (%q)", c.Name, why, target))
			}
		}
	}
	return out
}

// writeDests returns the arguments of a file-writing command that name its
// destination(s).
func writeDests(c Command) []string {
	var positional []string
	var out []string
	for i := 0; i < len(c.Args); i++ {
		a := c.Args[i]
		if a == "-t" || a == "--target-directory" {
			if i+1 < len(c.Args) {
				out = append(out, c.Args[i+1])
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "--target-directory=") {
			out = append(out, strings.TrimPrefix(a, "--target-directory="))
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		positional = append(positional, a)
	}
	switch c.Name {
	case "mkdir", "touch", "rm", "rmdir", "tee":
		out = append(out, positional...)
	default: // cp, mv, install, ln: last positional is the destination
		if len(out) == 0 && len(positional) > 1 {
			out = append(out, positional[len(positional)-1])
		}
	}
	return out
}

func checkPrivilegeEscalation(ctx *Context) []Finding {
	var out []Finding
	esc := map[string]bool{"sudo": true, "doas": true, "pkexec": true, "su": true}
	for _, c := range ctx.Commands() {
		// sudo/doas are unwrapped by newCommand, so inspect the raw first word.
		raw := basename(c.RawName)
		if esc[raw] || esc[c.Name] {
			out = append(out, c.finding("PB402", Error,
				"%s escalates privileges during a build; anything needing root belongs to pacman's install step", raw))
		}
	}
	return out
}

var setuidModeRe = regexp.MustCompile(`^[0-7]?[4267][0-7]{3}$|^[24][0-7]{3}$`)

func checkSetuid(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("chmod") {
		for _, a := range c.Args {
			symbolic := strings.Contains(a, "+s")
			numeric := setuidModeRe.MatchString(a) && (strings.HasPrefix(a, "4") || strings.HasPrefix(a, "2") || strings.HasPrefix(a, "6"))
			if symbolic || numeric {
				out = append(out, c.finding("PB403", Warn,
					"chmod %s creates a setuid/setgid file", a))
				break
			}
		}
	}
	for _, c := range ctx.CommandsNamed("install") {
		if mode, _, _ := installModeArg(c); isSetuidNumeric(mode) {
			out = append(out, c.finding("PB403", Warn,
				"install with mode %s creates a setuid/setgid file", mode))
		}
	}
	return out
}

// installModeArg finds the numeric mode an `install` command applies, returning
// the mode digits, the argument word carrying it, and the full replacement for
// that word with the setuid/setgid bits cleared.
func installModeArg(c Command) (mode string, word *syntax.Word, replacement string) {
	for i := 0; i < len(c.Args); i++ {
		a := c.Args[i]
		switch {
		case strings.HasPrefix(a, "--mode="):
			m := strings.TrimPrefix(a, "--mode=")
			return m, wordByValue(c, a), "--mode=" + clearSetuidBits(m)
		case a == "--mode" || a == "-m":
			if i+1 < len(c.Args) {
				m := c.Args[i+1]
				return m, wordByValue(c, m), clearSetuidBits(m)
			}
		default:
			if m := shortFlagMode(a); m != "" {
				return m, wordByValue(c, a), strings.TrimSuffix(a, m) + clearSetuidBits(m)
			}
		}
	}
	return "", nil, ""
}

// shortFlagMode extracts the mode digits from an install short-flag cluster
// ending in -m<mode>, e.g. "-Dm4755" -> "4755". install requires -m to be last
// in a cluster because it consumes the following value.
var shortFlagModeRe = regexp.MustCompile(`^-[A-Za-z]*m([0-7]{3,4})$`)

func shortFlagMode(a string) string {
	if m := shortFlagModeRe.FindStringSubmatch(a); m != nil {
		return m[1]
	}
	return ""
}

// --- PB404: install step not redirected into $pkgdir -----------------------

func checkInstallDestdir(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if c.Fn != "package" && !strings.HasPrefix(c.Fn, "package_") {
			continue
		}
		tool, ok := liveInstallCommand(c)
		if !ok || installBindsDestdir(c) || funcBindsDestdir(c.Unit, c.Fn) {
			continue
		}
		out = append(out, c.finding("PB404", Error,
			"`%s` in package() is not redirected into $pkgdir (set DESTDIR/--root/--prefix/--destdir)", tool))
	}
	return out
}

func liveInstallCommand(c Command) (string, bool) {
	switch c.Name {
	case "make":
		for _, a := range c.Args {
			if a == "install" || strings.HasPrefix(a, "install-") {
				return "make install", true
			}
		}
	case "ninja":
		if c.HasArg("install") {
			return "ninja install", true
		}
	case "cmake":
		if c.HasArg("--install") {
			return "cmake --install", true
		}
	case "meson":
		if c.Subcommand() == "install" || c.HasArg("install") {
			return "meson install", true
		}
	case "cargo":
		if c.Subcommand() == "install" {
			return "cargo install", true
		}
	case "pip", "pip3":
		if c.Subcommand() == "install" || c.HasArg("install") {
			return "pip install", true
		}
	case "python", "python3", "python2":
		if c.HasArg("setup.py") && c.HasArg("install") {
			return "python setup.py install", true
		}
	}
	return "", false
}

// installBindsDestdir reports whether the install command itself names a staging
// target: an inline DESTDIR/prefix env prefix, or any argument referencing
// $pkgdir/$DESTDIR.
func installBindsDestdir(c Command) bool {
	for _, as := range c.Call.Assigns {
		if as.Name == nil {
			continue
		}
		switch as.Name.Value {
		case "DESTDIR", "prefix", "PREFIX":
			return true
		}
	}
	for _, a := range c.Args {
		if strings.Contains(a, "$pkgdir") || strings.Contains(a, "$DESTDIR") ||
			strings.HasPrefix(a, "DESTDIR=") {
			return true
		}
	}
	return false
}

// funcBindsDestdir reports whether the named function assigns DESTDIR anywhere
// (e.g. `export DESTDIR="$pkgdir"` before the install step).
func funcBindsDestdir(u *pkgbuild.Unit, fn string) bool {
	fd := u.Functions[fn]
	if fd == nil {
		return false
	}
	found := false
	syntax.Walk(fd, func(n syntax.Node) bool {
		if as, ok := n.(*syntax.Assign); ok && as.Name != nil && as.Name.Value == "DESTDIR" {
			found = true
			return false
		}
		return true
	})
	return found
}

// --- PB405: writes to trust/privilege configuration ------------------------

var sensitivePaths = []struct{ prefix, why string }{
	{"/etc/pacman.conf", "pacman's configuration controls repositories and signature enforcement"},
	{"/etc/pacman.d", "pacman's configuration directory controls repositories and mirrors"},
	{"/etc/ld.so.preload", "/etc/ld.so.preload forces a library into every dynamically-linked process"},
	{"/etc/ld.so.conf", "the dynamic linker's search path affects every binary"},
	{"/etc/sudoers", "sudoers governs privilege escalation"},
}

func sensitiveWritePath(target string) string {
	t := strings.TrimSpace(target)
	for _, s := range sensitivePaths {
		if strings.HasPrefix(t, s.prefix) {
			return s.why
		}
	}
	return ""
}

func checkSensitiveWrites(ctx *Context) []Finding {
	var out []Finding
	units := ctx.Pkg.Units()
	for i := range units {
		u := &units[i]
		syntax.Walk(u.File, func(node syntax.Node) bool {
			r, ok := node.(*syntax.Redirect)
			if !ok || r.Word == nil {
				return true
			}
			switch r.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
			default:
				return true
			}
			target, _ := pkgbuild.RenderWord(r.Word, ctx.vars)
			if why := sensitiveWritePath(target); why != "" {
				out = append(out, findingAt("PB405", Critical, u.Path, r.Pos(),
					"redirection to %q: %s", target, why))
			}
			return true
		})
	}
	for _, c := range ctx.Commands() {
		if c.Name == "pacman-key" || basename(c.RawName) == "pacman-key" {
			out = append(out, c.finding("PB405", Critical,
				"pacman-key manipulates the pacman trust keyring"))
			continue
		}
		if !fileWriters[c.Name] {
			continue
		}
		for _, target := range writeDests(c) {
			if why := sensitiveWritePath(target); why != "" {
				out = append(out, c.finding("PB405", Critical, "%s writes to %q: %s", c.Name, target, why))
			}
		}
	}
	return out
}
