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
		Doc: "chmod u+s/g+s (or 4xxx/2xxx modes) creates setuid/setgid binaries — a privilege " +
			"boundary that deserves explicit review whenever a package ships one.",
		Check: checkSetuid,
	},
}

// prefixes always acceptable as write targets.
var allowedWritePrefixes = []string{
	"$pkgdir", "${pkgdir", "$srcdir", "${srcdir", "$startdir", "${startdir",
	"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/fd/",
	"/tmp/", "$TMPDIR", "${TMPDIR",
}

func writeTargetViolation(target string) string {
	t := strings.TrimSpace(target)
	if t == "" || strings.Contains(t, "\x00") {
		return ""
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

	writers := map[string]bool{
		"cp": true, "mv": true, "install": true, "ln": true, "tee": true,
		"mkdir": true, "touch": true, "rm": true, "rmdir": true,
	}
	for _, c := range ctx.Commands() {
		if !writers[c.Name] {
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
	return out
}
