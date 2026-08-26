package rules

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// PB3xx: code execution and obfuscation.
var execRules = []Rule{
	{
		ID:   "PB301",
		Name: "top-level-execution",
		Doc: "Commands outside any function run the moment the PKGBUILD is sourced — including by " +
			"tools that only wanted metadata (`makepkg --printsrcinfo`, AUR helpers rendering a " +
			"preview). Top-level code should be limited to variable assignments.",
		Check: checkTopLevelExec,
	},
	{
		ID:   "PB302",
		Name: "eval",
		Doc: "eval executes a string as code, defeating static review: what actually runs is " +
			"assembled at build time. Almost every legitimate use has a plain-bash equivalent.",
		Check: checkEval,
	},
	{
		ID:   "PB303",
		Name: "decode-and-execute",
		Doc: "Decoding embedded data (base64, xxd, openssl enc) and piping it into an interpreter " +
			"is the canonical way to smuggle a payload past human review. There is no legitimate " +
			"reason for a PKGBUILD to execute decoded blobs.",
		Check: checkDecodeExec,
	},
	{
		ID:   "PB304",
		Name: "download-and-execute",
		Doc: "Piping a download straight into an interpreter executes whatever the server chooses " +
			"to send, with no checksum, no review, and no record. This includes `eval \"$(curl ...)\"`, " +
			"`sh -c \"$(wget ...)\"` and `source <(curl ...)` variants.",
		Check: checkDownloadExec,
	},
	{
		ID:   "PB305",
		Name: "dev-tcp",
		Doc: "/dev/tcp and /dev/udp redirections are bash's built-in network sockets — in a " +
			"PKGBUILD they are typically reverse shells or exfiltration, never packaging.",
		Check: checkDevTCP,
	},
	{
		ID:   "PB306",
		Name: "unresolvable-command",
		Doc: "A command whose name comes from indirection (${!var}) or command substitution cannot " +
			"be statically reviewed. In a PKGBUILD, hiding *which program runs* is itself a signal: " +
			"obfuscation is what this rule flags.",
		Check: checkDynamicCommands,
	},
	{
		ID:   "PB307",
		Name: "obfuscated-payload",
		Doc: "Long hex-escape sequences or large base64-looking literals embedded in a build " +
			"script are how encoded payloads look at rest. Flagged for human review.",
		Check: checkObfuscatedLiterals,
	},
	{
		ID:   "PB308",
		Name: "makepkg-function-override",
		Doc: "makepkg sources the PKGBUILD after defining its own internal functions, so a top-level " +
			"function that reuses an internal name (download_sources, verify_integrity_one, " +
			"create_package, …) silently replaces makepkg's implementation — a way to disable integrity " +
			"checks or tamper with fetching and packaging. Package functions are prepare/build/check/" +
			"package/package_*/pkgver only.",
		Check: checkMakepkgFuncOverride,
	},
	{
		ID:   "PB309",
		Name: "hidden-unicode",
		Doc: "Bidirectional-override and invisible/zero-width characters can make the rendered source " +
			"differ from what the shell executes (the \"Trojan Source\" class of attacks). A PKGBUILD is " +
			"ASCII shell; these controls have no legitimate place in it.",
		Check: checkHiddenUnicode,
	},
}

// criticalMakepkgFuncs are libmakepkg/makepkg internal functions whose behavior
// governs integrity verification, source fetching/extraction, or packaging.
// Redefining any of them at the top level of a PKGBUILD hijacks makepkg itself.
var criticalMakepkgFuncs = map[string]bool{
	// integrity & signature verification
	"check_checksums": true, "check_source_integrity": true, "check_pgpsigs": true,
	"check_option": true, "verify_file_signature": true, "verify_git_signature": true,
	"verify_integrity_one": true, "verify_integrity_sums": true, "source_has_signatures": true,
	// download
	"download_sources": true, "download_file": true, "download_git": true,
	"download_svn": true, "download_hg": true, "download_bzr": true,
	"download_fossil": true, "download_local": true,
	"get_downloadclient": true, "get_vcsclient": true,
	// source loading & extraction
	"extract_sources": true, "extract_file": true, "extract_git": true,
	"extract_svn": true, "extract_hg": true, "extract_bzr": true, "extract_fossil": true,
	"source_buildfile": true, "source_safe": true, "source_files": true,
	"source_makepkg_config": true,
	// packaging & phase runners
	"create_package": true, "create_package_signatures": true, "create_signature": true,
	"run_function": true, "run_function_safe": true, "run_pacman": true,
	"run_prepare": true, "run_build": true, "run_check": true, "run_verify": true,
	"run_package": true, "run_single_packaging": true, "run_split_packaging": true,
	"write_srcinfo": true,
}

func checkMakepkgFuncOverride(ctx *Context) []Finding {
	var out []Finding
	for name, fd := range ctx.Pkg.PKGBUILD.Functions {
		if criticalMakepkgFuncs[name] {
			out = append(out, findingAt("PB308", Critical, ctx.Pkg.PKGBUILD.Path, fd.Pos(),
				"top-level function %q shadows a makepkg internal of the same name, replacing its behavior", name))
		}
	}
	return out
}

// bidiControls are directional-override characters that can reorder how a line
// renders without changing what the shell executes.
var bidiControls = map[rune]string{
	0x202A: "U+202A LEFT-TO-RIGHT EMBEDDING", 0x202B: "U+202B RIGHT-TO-LEFT EMBEDDING",
	0x202C: "U+202C POP DIRECTIONAL FORMATTING", 0x202D: "U+202D LEFT-TO-RIGHT OVERRIDE",
	0x202E: "U+202E RIGHT-TO-LEFT OVERRIDE", 0x2066: "U+2066 LEFT-TO-RIGHT ISOLATE",
	0x2067: "U+2067 RIGHT-TO-LEFT ISOLATE", 0x2068: "U+2068 FIRST STRONG ISOLATE",
	0x2069: "U+2069 POP DIRECTIONAL ISOLATE",
}

// invisibleChars are zero-width or otherwise non-rendering characters that can
// hide text or split tokens invisibly.
var invisibleChars = map[rune]string{
	0x200B: "U+200B ZERO WIDTH SPACE", 0x200C: "U+200C ZERO WIDTH NON-JOINER",
	0x200D: "U+200D ZERO WIDTH JOINER", 0x2060: "U+2060 WORD JOINER",
	0xFEFF: "U+FEFF ZERO WIDTH NO-BREAK SPACE", 0x00AD: "U+00AD SOFT HYPHEN",
}

func checkHiddenUnicode(ctx *Context) []Finding {
	var out []Finding
	units := ctx.Pkg.Units()
	for i := range units {
		u := &units[i]
		for lineNo, line := range strings.Split(string(u.Raw), "\n") {
			for _, r := range line {
				if name, ok := bidiControls[r]; ok {
					out = append(out, Finding{RuleID: "PB309", Severity: Error,
						Message: "bidirectional control character " + name + " can hide what the shell runs",
						Path:    u.Path, Line: lineNo + 1, Col: 1})
					break
				}
			}
			for _, r := range line {
				if name, ok := invisibleChars[r]; ok {
					out = append(out, Finding{RuleID: "PB309", Severity: Warn,
						Message: "invisible character " + name + " embedded in source",
						Path:    u.Path, Line: lineNo + 1, Col: 1})
					break
				}
			}
		}
	}
	return out
}

// Top-level builtins that only manipulate shell/package state.
var benignTopLevel = map[string]bool{
	"unset": true, "export": true, "declare": true, "typeset": true, "local": true,
	"readonly": true, "set": true, "shopt": true, ":": true, "true": true, "false": true,
}

func checkTopLevelExec(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if c.Fn != "" || c.Unit.Scriptlet {
			continue
		}
		if benignTopLevel[c.Name] {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.RawName
		}
		out = append(out, c.finding("PB301", Critical,
			"%q executes at PKGBUILD top level — it runs whenever the file is sourced, even for metadata extraction", name))
	}
	return out
}

var shellSinks = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"python": true, "python3": true, "python2": true, "perl": true, "ruby": true, "node": true,
}

var downloaders = map[string]bool{"curl": true, "wget": true, "fetch": true, "aria2c": true, "axel": true}

var decoders = map[string]bool{"base64": true, "base32": true, "xxd": true, "uudecode": true, "openssl": true}

func checkEval(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if c.Name != "eval" {
			continue
		}
		sev := Error
		msg := "eval assembles and executes code at build time, defeating static review"
		for _, w := range c.Call.Args[1:] {
			if wordContainsCommand(w, downloaders) {
				sev = Critical
				msg = "eval executes the output of a network download"
			}
		}
		out = append(out, c.finding("PB302", sev, "%s", msg))
	}
	return out
}

func checkDecodeExec(ctx *Context) []Finding {
	return ctx.checkPipeInto(decoders, func(c Command) bool {
		// openssl only decodes with `enc -d` / base64 -d style flags.
		if c.Name == "openssl" {
			return c.Subcommand() == "enc" || c.Subcommand() == "base64"
		}
		if c.Name == "base64" || c.Name == "base32" {
			return c.HasArg("-d") || c.HasArg("--decode") || c.HasArg("-D")
		}
		if c.Name == "xxd" {
			return c.HasArg("-r")
		}
		return true
	}, "PB303", "decoded data is piped into %s: embedded payload execution")
}

func checkDownloadExec(ctx *Context) []Finding {
	out := ctx.checkPipeInto(downloaders, func(Command) bool { return true },
		"PB304", "a network download is piped straight into %s and executed")

	// eval "$(curl ...)" is handled by PB302; here: sh -c "$(curl ...)" and
	// source <(curl ...).
	for _, c := range ctx.Commands() {
		if shellSinks[c.Name] || c.Name == "source" || c.Name == "." {
			for _, w := range c.Call.Args[1:] {
				if wordContainsCommand(w, downloaders) {
					out = append(out, c.finding("PB304", Critical,
						"%s executes the output of a network download", c.Name))
					break
				}
			}
		}
	}
	return out
}

// checkPipeInto flags pipelines where a command from sources (passing
// qualify) ends up in an interpreter sink.
func (ctx *Context) checkPipeInto(sources map[string]bool, qualify func(Command) bool, id, format string) []Finding {
	var out []Finding
	units := ctx.Pkg.Units()
	for i := range units {
		u := &units[i]
		for _, segs := range pipelines(u.File, u.Functions) {
			var sink string
			last := segs[len(segs)-1]
			sinkName := stmtCommandName(last, ctx.vars)
			if shellSinks[sinkName] {
				sink = sinkName
			} else {
				continue
			}
			for _, seg := range segs[:len(segs)-1] {
				call, ok := seg.Cmd.(*syntax.CallExpr)
				if !ok || len(call.Args) == 0 {
					continue
				}
				c := ctx.newCommand(u, "", seg, call)
				if sources[c.Name] && qualify(c) {
					out = append(out, findingAt(id, Critical, u.Path, seg.Pos(), format, sink))
					break
				}
			}
		}
	}
	return out
}

func checkDevTCP(ctx *Context) []Finding {
	var out []Finding
	units := ctx.Pkg.Units()
	for i := range units {
		u := &units[i]
		syntax.Walk(u.File, func(node syntax.Node) bool {
			r, ok := node.(*syntax.Redirect)
			if !ok {
				return true
			}
			if r.Word == nil {
				return true
			}
			s, _ := renderPlain(r.Word)
			if strings.Contains(s, "/dev/tcp/") || strings.Contains(s, "/dev/udp/") {
				out = append(out, findingAt("PB305", Critical, u.Path, r.Pos(),
					"raw %s socket redirection", s))
			}
			return true
		})
	}
	return out
}

func checkDynamicCommands(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.Commands() {
		if c.Name != "" || len(c.Call.Args) == 0 {
			continue
		}
		first := c.Call.Args[0]
		indirect := false
		syntax.Walk(first, func(node syntax.Node) bool {
			if pe, ok := node.(*syntax.ParamExp); ok && pe.Excl {
				indirect = true
			}
			return true
		})
		switch {
		case indirect:
			out = append(out, c.finding("PB306", Error,
				"command name via ${!indirection}: what runs cannot be determined statically"))
		case c.Dynamic:
			out = append(out, c.finding("PB306", Warn,
				"command name %q is not statically resolvable", c.RawName))
		}
	}
	return out
}

var (
	hexRunRe     = regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){8,}`)
	base64BlobRe = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)
)

func checkObfuscatedLiterals(ctx *Context) []Finding {
	var out []Finding
	units := ctx.Pkg.Units()
	for i := range units {
		u := &units[i]
		for lineNo, line := range strings.Split(string(u.Raw), "\n") {
			if hexRunRe.MatchString(line) {
				out = append(out, Finding{RuleID: "PB307", Severity: Warn,
					Message: "long hex-escape run looks like an encoded payload",
					Path:    u.Path, Line: lineNo + 1, Col: 1})
			}
			if m := base64BlobRe.FindString(line); m != "" && !looksLikeDigestContext(line) {
				out = append(out, Finding{RuleID: "PB307", Severity: Warn,
					Message: "large base64-like literal embedded in build script",
					Path:    u.Path, Line: lineNo + 1, Col: 1})
			}
		}
	}
	return out
}

// looksLikeDigestContext avoids flagging checksum arrays: hex digests are
// subsets of the base64 alphabet.
func looksLikeDigestContext(line string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.Contains(trimmed, "sums") {
		return true
	}
	m := base64BlobRe.FindString(line)
	return regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(m)
}
