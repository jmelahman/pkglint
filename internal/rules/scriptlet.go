package rules

import (
	"strings"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

// PB5xx: install scriptlets. These run as root on the user's machine at
// install time, so network access and persistence mechanisms are judged much
// more harshly than in the build itself. The exec/obfuscation rules (PB3xx)
// and filesystem rules (PB4xx) also run over scriptlets; the rules here are
// scriptlet-specific.
var scriptletRules = []Rule{
	{
		ID:   "PB501",
		Name: "network-in-scriptlet",
		Doc: "Install scriptlets run as root during pacman transactions. A scriptlet that talks " +
			"to the network executes unreviewable remote input at the worst possible moment — " +
			"this is how the 2018 acroread AUR compromise delivered its payload.",
		Check: checkScriptletNetwork,
	},
	{
		ID:   "PB502",
		Name: "scriptlet-persistence",
		Doc: "Files a package ships belong in package(), tracked and removed by pacman. A " +
			"scriptlet that edits crontabs, systemd units, shell profiles or autostart entries, or " +
			"creates login-capable users, is installing untracked persistence — a classic backdoor " +
			"pattern.",
		Check: checkScriptletPersistence,
	},
}

func checkScriptletNetwork(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if !c.Unit.Scriptlet {
			continue
		}
		fetches, ok := networkCommands[c.Name]
		if !ok || !fetches(c) {
			continue
		}
		out = append(out, c.finding("PB501", Critical,
			"%s accesses the network from an install scriptlet running as root", c.Name))
	}
	return out
}

var persistencePathHints = []string{
	"/etc/cron", "/var/spool/cron", "/etc/systemd/system", "/usr/lib/systemd/system",
	"/etc/profile", "/etc/bash.bashrc", "/etc/zsh", ".bashrc", ".zshrc", ".profile",
	".config/autostart", "/etc/xdg/autostart", "/etc/ld.so.preload", "/etc/rc.local",
	"/etc/sudoers", "authorized_keys",
}

func checkScriptletPersistence(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if !c.Unit.Scriptlet {
			continue
		}
		switch c.Name {
		case "crontab":
			out = append(out, c.finding("PB502", Critical, "scriptlet installs a crontab"))
			continue
		case "useradd", "usermod":
			for i, a := range c.Args {
				if a == "-s" && i+1 < len(c.Args) {
					shell := c.Args[i+1]
					if !strings.Contains(shell, "nologin") && !strings.Contains(shell, "false") {
						out = append(out, c.finding("PB502", Error,
							"scriptlet creates a user with login shell %q; system users should get nologin", shell))
					}
				}
			}
			continue
		case "systemctl":
			if c.HasArg("enable") || c.HasArg("--now") {
				out = append(out, c.finding("PB502", Warn,
					"scriptlet enables a systemd unit; prefer documenting this or shipping a preset"))
			}
			continue
		}
		for _, a := range c.Args {
			// The hints overlap (/etc/zsh and .zshrc both match /etc/zsh/.zshrc),
			// so report the first match only.
			for _, hint := range persistencePathHints {
				if strings.Contains(a, hint) {
					out = append(out, c.finding("PB502", Error,
						"scriptlet touches %q, a persistence location outside pacman's tracking", a))
					break
				}
			}
		}
	}

	// Redirection targets (echo ... >> /var/spool/cron/root) count too.
	for _, u := range ctx.Pkg.Scriptlets {
		syntax.Walk(u.File, func(node syntax.Node) bool {
			r, ok := node.(*syntax.Redirect)
			if !ok || r.Word == nil {
				return true
			}
			target, _ := pkgbuild.RenderWord(r.Word, ctx.vars)
			for _, hint := range persistencePathHints {
				if strings.Contains(target, hint) {
					out = append(out, findingAt("PB502", Critical, u.Path, r.Pos(),
						"scriptlet writes to %q, a persistence location outside pacman's tracking", target))
					break
				}
			}
			return true
		})
	}
	return out
}
