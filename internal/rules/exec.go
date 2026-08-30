package rules

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// PB3xx: code execution and obfuscation.
var execRules = []Rule{
	{
		ID:       "PB301",
		Name:     "top-level-execution",
		Severity: Critical,
		Doc: "Commands outside any function run the moment the PKGBUILD is sourced — including by " +
			"tools that only wanted metadata (`makepkg --printsrcinfo`, AUR helpers rendering a " +
			"preview). Top-level code should be limited to variable assignments.",
		Check: checkTopLevelExec,
	},
	{
		ID:       "PB302",
		Name:     "eval",
		Severity: Error, MaxSeverity: Critical, // critical when the evaluated string is downloaded
		Doc: "eval executes a string as code, defeating static review: what actually runs is " +
			"assembled at build time. Almost every legitimate use has a plain-bash equivalent.",
		Check: checkEval,
	},
	{
		ID:       "PB303",
		Name:     "decode-and-execute",
		Severity: Critical,
		Doc: "Decoding embedded data (base64, xxd, openssl enc) and piping it into an interpreter " +
			"is the canonical way to smuggle a payload past human review. There is no legitimate " +
			"reason for a PKGBUILD to execute decoded blobs.",
		Check: checkDecodeExec,
	},
	{
		ID:       "PB304",
		Name:     "download-and-execute",
		Severity: Critical,
		Doc: "Piping a download straight into an interpreter executes whatever the server chooses " +
			"to send, with no checksum, no review, and no record. This includes `eval \"$(curl ...)\"`, " +
			"`sh -c \"$(wget ...)\"` and `source <(curl ...)` variants.",
		Check: checkDownloadExec,
	},
	{
		ID:       "PB305",
		Name:     "dev-tcp",
		Severity: Critical,
		Doc: "/dev/tcp and /dev/udp redirections are bash's built-in network sockets — in a " +
			"PKGBUILD they are typically reverse shells or exfiltration, never packaging.",
		Check: checkDevTCP,
	},
	{
		ID:       "PB306",
		Name:     "unresolvable-command",
		Severity: Warn, MaxSeverity: Error, // error for ${!indirection}, which hides the name outright
		Doc: "A command whose name comes from indirection (${!var}) or command substitution cannot " +
			"be statically reviewed. In a PKGBUILD, hiding *which program runs* is itself a signal: " +
			"obfuscation is what this rule flags.",
		Check: checkDynamicCommands,
	},
	{
		ID:       "PB307",
		Name:     "obfuscated-payload",
		Severity: Warn,
		Doc: "Long hex-escape sequences or large base64-looking literals embedded in a build " +
			"script are how encoded payloads look at rest. Flagged for human review.",
		Check: checkObfuscatedLiterals,
	},
	{
		ID:       "PB308",
		Name:     "makepkg-function-override",
		Severity: Critical,
		Doc: "makepkg sources the PKGBUILD after defining its own internal functions, so a top-level " +
			"function that reuses an internal name (download_sources, verify_integrity_one, " +
			"create_package, …) silently replaces makepkg's implementation — a way to disable integrity " +
			"checks or tamper with fetching and packaging. Package functions are prepare/build/check/" +
			"package/package_*/pkgver only.",
		Check: checkMakepkgFuncOverride,
	},
	{
		ID:       "PB309",
		Name:     "hidden-unicode",
		Severity: Warn, MaxSeverity: Error, // error for bidi controls, which reorder what you read
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

// hasNonASCII reports whether b contains any byte outside 7-bit ASCII, which
// is true of every byte of every multi-byte UTF-8 encoding.
func hasNonASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return true
		}
	}
	return false
}

func checkHiddenUnicode(ctx *Context) []Finding {
	var out []Finding
	units := ctx.Pkg.Units()
	for i := range units {
		u := &units[i]
		// Every rune in both tables is above U+007F, so it encodes to bytes
		// that all have the high bit set. A unit with no such byte cannot
		// contain one, and almost no PKGBUILD does — which makes this scan
		// worth doing before splitting the file into lines and decoding each
		// one twice.
		if !hasNonASCII(u.Raw) {
			continue
		}
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

// pureTopLevel are commands whose whole effect is to test a condition or write
// to stdout/stderr: they open no file, spawn no interpreter, and reach no
// network. Arch and build-flag guards (`if [ "$CARCH" = i686 ]` selecting a
// depends+=()) and status banners are the bulk of what this rule used to
// report, and scoring them alongside an unauthenticated `curl | sh` buried the
// findings worth acting on.
//
// `[` and `test` also settle an asymmetry: `[[ ]]` and `(( ))` parse as
// TestClause and ArithmCmd rather than CallExpr, so they never reached this
// rule at all. Flagging one spelling of a condition and not the other meant a
// stylistic rewrite could move a package from F to A.
var pureTopLevel = map[string]bool{
	"[": true, "test": true,
	"echo": true, "printf": true, "cat": true, "tput": true,
	// A pure reader: grep has no write form at all, and `grep -q` guards are
	// how PKGBUILDs probe the host for a feature before appending a depends.
	"grep": true, "egrep": true, "fgrep": true,
	// libmakepkg's message API, sourced into the PKGBUILD's shell before it
	// runs. PB907 already rates these a portability nit rather than a hazard.
	"msg": true, "msg2": true, "warning": true, "error": true, "plain": true,
}

// pureTopLevelUse reports whether this invocation is one of the pure ones.
// date and sed are pure in their common forms but each keeps one escape hatch
// into system state, so they are judged per call rather than by name.
func pureTopLevelUse(c Command) bool {
	if pureTopLevel[c.Name] {
		return true
	}
	switch c.Name {
	case "date":
		// `export KBUILD_BUILD_TIMESTAMP="$(date -Ru…)"` is the kernel
		// packages' reproducible-builds idiom, verbatim from core/linux.
		// Reading the clock is pure; setting it is not.
		return !dateSetsClock(c)
	case "sed":
		// Filtering a pipe is pure; -i and the w script forms write files.
		return !sedInPlace(c) && !sedWritesFile(c)
	}
	return false
}

// dateSetsClock reports whether this date invocation sets the system clock
// rather than printing it: GNU -s/--set, or the POSIX operand form — a
// positional argument not starting with '+' (`date 0501120026`).
func dateSetsClock(c Command) bool {
	for i := 0; i < len(c.Args); i++ {
		a := c.Args[i]
		switch {
		case strings.HasPrefix(a, "--"):
			if strings.HasPrefix(a, "--set") {
				return true
			}
			// A detached value follows its option; don't read it as the
			// POSIX operand form.
			if a == "--date" || a == "--file" || a == "--reference" {
				i++
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if strings.ContainsRune(a[1:], 's') {
				return true // -s anywhere in a cluster is --set
			}
			// A trailing -d/-f/-r takes the next word as its value; attached
			// values (-d@1234) are already part of this argument.
			switch a[len(a)-1] {
			case 'd', 'f', 'r':
				i++
			}
		case !strings.HasPrefix(a, "+"):
			return true // POSIX operand form sets the clock
		}
	}
	return false
}

// sedWriteRe conservatively matches sed's file-writing script forms: the
// `w file` / `W file` command (possibly address-prefixed) and the `s///w file`
// flag. A replacement that merely contains " w " keeps the finding — for this
// rule that is the right direction to be wrong.
var sedWriteRe = regexp.MustCompile(`(^|[;{[:space:]/0-9$])[wW][[:space:]]`)

func sedWritesFile(c Command) bool {
	for _, a := range c.Args {
		// Telling script arguments from input files apart needs full option
		// parsing; checking every non-flag argument over-matches at worst.
		if !strings.HasPrefix(a, "-") && sedWriteRe.MatchString(a) {
			return true
		}
	}
	return false
}

// redirectsOutput reports whether the statement sends its output to a file,
// which is what separates a banner from a write: `cat <<EOF > helper.sh` at
// the top level drops a file on disk the moment the PKGBUILD is sourced.
func redirectsOutput(stmt *syntax.Stmt) bool {
	for _, r := range stmt.Redirs {
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
			return true
		}
	}
	return false
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
		// eval belongs to PB302, which reports it wherever it appears and
		// escalates to Critical on its own when the evaluated string was
		// downloaded. Reporting it here as well stacks a second Critical on
		// the identical statement without adding anything a reader could act
		// on differently.
		if c.Name == "eval" {
			continue
		}
		// A PKGBUILD that defines its own echo/warning/… gets no exemption:
		// the name would say "banner" while the body did the work.
		if pureTopLevelUse(c) && !redirectsOutput(c.Stmt) && !ctx.definesFunc(c, c.Name) {
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

// scriptInterpreters are the shellSinks that run a program named on their own
// command line. A shell executes stdin by default — `curl … | sh` runs what it
// downloaded — but `python3 -c '<program>'` and `node parse.js` were handed a
// program that is already on disk and under review, so the piped response is
// that program's *input*, not code. The AUR idiom this distinguishes is the
// pkgver() helper that fetches a registry's JSON and prints one field.
var scriptInterpreters = map[string]bool{
	"python": true, "python3": true, "python2": true,
	"perl": true, "ruby": true, "node": true,
}

// sinkExecutesStdin reports whether a pipeline's terminating interpreter treats
// what it reads as code. Shells always do. A scriptInterpreter only does so
// when given no program of its own, or an explicit "-" naming stdin.
func sinkExecutesStdin(c Command) bool {
	if !scriptInterpreters[c.Name] {
		return true // a shell: stdin is the script
	}
	for _, a := range c.Args {
		if a == "-" {
			return true // read the program from stdin
		}
		if strings.HasPrefix(a, "-") {
			continue // a flag; -c/-e/-m carry their program in the next word
		}
		// A program to run, so stdin is normally its input — unless the
		// program itself hands stdin to an evaluator, which is the same
		// download-and-execute with one more hop. Matching the literal is
		// conservative on purpose: over-reporting here costs a review, and
		// under-reporting costs the finding this rule exists for.
		return stdinEvalRe.MatchString(a)
	}
	return true // bare interpreter: stdin is the script
}

// stdinEvalRe matches the evaluator names an inline interpreter program would
// use to execute what it read, across the scriptInterpreters' languages.
var stdinEvalRe = regexp.MustCompile(`\b(exec|eval|compile|system|instance_eval|Function)\b`)

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
		for _, segs := range pipelines(u.File) {
			last := segs[len(segs)-1]
			sinkName := stmtCommandName(last, ctx.vars)
			if !shellSinks[sinkName] {
				continue
			}
			if call, ok := last.Cmd.(*syntax.CallExpr); ok &&
				!sinkExecutesStdin(ctx.newCommand(u, "", last, call)) {
				continue
			}
			sink := sinkName
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
