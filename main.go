// pkglint is a security-focused linter for Arch Linux PKGBUILDs.
//
// It statically analyzes PKGBUILDs and install scriptlets — never sourcing
// them — and reports integrity, hermeticity, and code-execution findings
// with an overall letter grade per package.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jmelahman/pkglint/internal/alpmdb"
	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"github.com/jmelahman/pkglint/internal/pkgfile"
	"github.com/jmelahman/pkglint/internal/report"
	"github.com/jmelahman/pkglint/internal/rules"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, stdout io.Writer) int {
	var (
		format     string
		failOn     string
		ignore     string
		color      string
		listRules  bool
		doFix      bool
		unsafeFix  bool
		diff       bool
		offline    bool
		noInline   bool
		addIgnores bool
		verbose    bool
	)

	code := 0
	cmd := &cobra.Command{
		Use:   "pkglint [flags] [path ...]",
		Short: "security-focused linter for Arch Linux packages",
		Long: `pkglint statically analyzes PKGBUILDs and install scriptlets — never
sourcing them — and reports integrity, hermeticity, and code-execution
findings with an overall letter grade per package. Built packages
(*.pkg.tar.*) are analyzed too: ELF hardening and placement, dependencies
inferred from linked libraries and script interpreters, and filesystem
hygiene — never executing anything from the package.

paths are package directories, PKGBUILD files, or built package
archives (default: .)`,
		Version:       version,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, paths []string) error {
			if listRules {
				for _, r := range rules.Registry() {
					fmt.Fprintf(stdout, "%s %-24s %s\n", r.ID, r.Name, r.Doc)
				}
				return nil
			}
			if addIgnores {
				if doFix || unsafeFix || noInline {
					return fmt.Errorf("--add-ignores cannot be combined with --fix, --unsafe-fix, or --no-inline-ignores")
				}
				code = runAddIgnores(paths, ignoreSet(ignore), diff, stdout)
				return nil
			}
			if doFix || unsafeFix {
				level := rules.FixSafe
				if unsafeFix {
					level = rules.FixUnsafe
				}
				code = runFix(paths, ignoreSet(ignore), level, diff, offline, noInline, stdout)
				return nil
			}
			code = lint(paths, format, failOn, ignore, color, noInline, verbose, stdout)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or sarif")
	cmd.Flags().StringVar(&color, "color", "auto", "colorize text output: auto, always, or never")
	cmd.Flags().StringVar(&failOn, "fail-on", "error", "exit non-zero when a finding is at or above this severity (info, warn, error, critical, or never)")
	cmd.Flags().StringVar(&ignore, "ignore", "", "comma-separated rule IDs to disable, e.g. PB105,PB206")
	cmd.Flags().BoolVar(&listRules, "rules", false, "print all rules and exit")
	cmd.Flags().BoolVar(&doFix, "fix", false, "apply safe auto-fixes in place")
	cmd.Flags().BoolVar(&unsafeFix, "unsafe-fix", false, "apply safe and behavior-changing auto-fixes in place (implies --fix)")
	cmd.Flags().BoolVar(&diff, "diff", false, "with --fix/--unsafe-fix/--add-ignores: show changes instead of writing them")
	cmd.Flags().BoolVar(&offline, "offline", false, "with --fix: skip fixes needing network access (e.g. resolving VCS refs)")
	cmd.Flags().BoolVar(&noInline, "no-inline-ignores", false, "disregard '# pkglint: ignore=' directives, reporting the findings they suppress (audit a package without trusting its annotations)")
	cmd.Flags().BoolVar(&addIgnores, "add-ignores", false, "insert '# pkglint: ignore=' directives suppressing every current finding")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "text output: list packages with no findings individually instead of only in the summary")
	cmd.SetVersionTemplate("pkglint {{.Version}}\n")
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(os.Stderr)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "pkglint:", err)
		fmt.Fprintln(os.Stderr, "run 'pkglint --help' for usage")
		return 2
	}
	return code
}

// ignoreSet parses a comma-separated rule-ID list into a set.
func ignoreSet(csv string) map[string]bool {
	ignored := map[string]bool{}
	for _, id := range strings.Split(csv, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ignored[id] = true
		}
	}
	return ignored
}

// lint runs the rules over each path and renders the reports, returning the
// process exit code. A path may be a package directory / PKGBUILD (static
// PKGBUILD analysis) or a built .pkg.tar.* archive (package analysis).
// noInline disregards the packages' own inline-ignore directives, so findings
// they suppress are reported anyway. verbose lists findings-free packages in
// text output, which otherwise only counts them in the closing summary.
func lint(paths []string, format, failOn, ignore, color string, noInline, verbose bool, stdout io.Writer) int {
	ignored := ignoreSet(ignore)

	if len(paths) == 0 {
		paths = []string{"."}
	}

	// The pacman local database backs the dependency-inference rules; loaded
	// once, and only if a package archive is actually being linted. A missing
	// database (non-Arch host) yields nil, which disables just those rules.
	var db *alpmdb.DB
	dbLoaded := false
	localDB := func() *alpmdb.DB {
		if !dbLoaded {
			dbLoaded = true
			db, _ = alpmdb.Load(alpmdb.DefaultRoot)
		}
		return db
	}

	var reports []report.PackageReport
	for _, path := range paths {
		if pkgfile.IsPackagePath(path) {
			pkg, err := pkgfile.Load(path)
			if err != nil {
				reports = append(reports, report.NewError(path, err))
				continue
			}
			reports = append(reports, report.New(path, rules.RunPackage(pkg, localDB(), ignored)))
			continue
		}
		pkg, err := pkgbuild.Load(path)
		if err != nil {
			reports = append(reports, report.NewError(path, err))
			continue
		}
		if noInline {
			pkg.Suppressions = nil
		}
		findings := rules.Run(pkg, ignored)
		reports = append(reports, report.New(path, findings))
	}

	switch format {
	case "json":
		if err := report.RenderJSON(stdout, reports); err != nil {
			fmt.Fprintln(os.Stderr, "pkglint:", err)
			return 2
		}
	case "sarif":
		if err := report.RenderSARIF(stdout, reports); err != nil {
			fmt.Fprintln(os.Stderr, "pkglint:", err)
			return 2
		}
	case "text":
		colorize, err := colorEnabled(color, stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pkglint:", err)
			return 2
		}
		report.RenderText(stdout, reports, colorize, verbose)
	default:
		fmt.Fprintf(os.Stderr, "pkglint: unknown format %q\n", format)
		return 2
	}

	if failOn == "never" {
		return 0
	}
	sev, err := rules.ParseSeverity(failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pkglint:", err)
		return 2
	}
	if report.ExceedsThreshold(reports, sev) {
		return 1
	}
	return 0
}

// colorEnabled decides whether text output gets ANSI colors. "auto" enables
// them only when writing to a terminal, and defers to the NO_COLOR convention
// (https://no-color.org) and TERM=dumb; an explicit --color=always overrides
// both.
func colorEnabled(mode string, w io.Writer) (bool, error) {
	switch mode {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "auto":
		if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
			return false, nil
		}
		f, ok := w.(*os.File)
		if !ok {
			return false, nil
		}
		// A terminal presents as a character device; a pipe or regular file
		// does not. This keeps colors out of redirected output without a
		// platform-specific isatty call.
		fi, err := f.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0, nil
	default:
		return false, fmt.Errorf("unknown color mode %q (want auto, always, or never)", mode)
	}
}

// runFix applies auto-fixes at the given level, writing files in place (or,
// with diff, printing the changes it would make). It also nudges toward the
// manual follow-ups for findings that can't be rewritten mechanically.
// noInline disregards inline-ignore directives, so suppressed fixes apply too.
func runFix(paths []string, ignore map[string]bool, level rules.FixLevel, diff, offline, noInline bool, stdout io.Writer) int {
	if len(paths) == 0 {
		paths = []string{"."}
	}
	env := &rules.FixEnv{}
	if !offline {
		env.ResolveRef = resolveGitRef
	}
	rc := 0
	for _, path := range paths {
		if pkgfile.IsPackagePath(path) {
			fmt.Fprintf(stdout, "%s: built packages have no auto-fixable findings; fix the PKGBUILD and rebuild\n", rel(path))
			continue
		}
		pkg, err := pkgbuild.Load(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pkglint: %s: %v\n", path, err)
			rc = 2
			continue
		}
		if noInline {
			pkg.Suppressions = nil
		}
		applied := 0
		for _, r := range rules.Fix(pkg, ignore, level, env) {
			if !r.Changed() {
				continue
			}
			for _, e := range r.Applied {
				applied++
				fmt.Fprintf(stdout, "%s:%d: [%s] %s\n", rel(e.Path), e.Line, e.RuleID, e.Desc)
				if diff {
					fmt.Fprint(stdout, editHunk(r.Original, e))
				}
			}
			if !diff {
				if err := writeFixed(r.Path, r.Fixed); err != nil {
					fmt.Fprintf(os.Stderr, "pkglint: writing %s: %v\n", r.Path, err)
					rc = 2
				}
			}
		}
		for _, s := range manualSuggestions(pkg, ignore) {
			fmt.Fprintf(stdout, "%s: %s\n", rel(path), s)
		}
		switch {
		case applied == 0:
			fmt.Fprintf(stdout, "%s: no auto-fixable findings\n", rel(path))
		case diff:
			fmt.Fprintf(stdout, "%s: %d fix(es) would be applied (dry run)\n", rel(path), applied)
		default:
			fmt.Fprintf(stdout, "%s: applied %d fix(es)\n", rel(path), applied)
		}
	}
	return rc
}

// runAddIgnores inserts inline-ignore directives suppressing every finding the
// packages currently report (or, with diff, prints the insertions it would
// make). It is the reviewed-and-accepted counterpart to --fix: the findings
// stay in the file as annotations instead of being repaired.
func runAddIgnores(paths []string, ignore map[string]bool, diff bool, stdout io.Writer) int {
	if len(paths) == 0 {
		paths = []string{"."}
	}
	rc := 0
	for _, path := range paths {
		if pkgfile.IsPackagePath(path) {
			fmt.Fprintf(stdout, "%s: built packages cannot carry ignore directives; annotate the PKGBUILD instead\n", rel(path))
			continue
		}
		pkg, err := pkgbuild.Load(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pkglint: %s: %v\n", path, err)
			rc = 2
			continue
		}
		applied := 0
		for _, r := range rules.AddIgnores(pkg, ignore) {
			if !r.Changed() {
				continue
			}
			for _, e := range r.Applied {
				applied++
				fmt.Fprintf(stdout, "%s:%d: [%s] %s\n", rel(e.Path), e.Line, e.RuleID, e.Desc)
				if diff {
					fmt.Fprint(stdout, editHunk(r.Original, e))
				}
			}
			if !diff {
				if err := writeFixed(r.Path, r.Fixed); err != nil {
					fmt.Fprintf(os.Stderr, "pkglint: writing %s: %v\n", r.Path, err)
					rc = 2
				}
			}
		}
		switch {
		case applied == 0:
			fmt.Fprintf(stdout, "%s: no findings to suppress\n", rel(path))
		case diff:
			fmt.Fprintf(stdout, "%s: %d ignore directive(s) would be added (dry run)\n", rel(path), applied)
		default:
			fmt.Fprintf(stdout, "%s: added %d ignore directive(s)\n", rel(path), applied)
		}
	}
	return rc
}

// manualSuggestions returns one-line nudges for findings whose remediation is
// real but not a mechanical rewrite pkglint should perform for the user.
func manualSuggestions(pkg *pkgbuild.Package, ignore map[string]bool) []string {
	byRule := map[string]bool{}
	for _, f := range rules.Run(pkg, ignore) {
		byRule[f.RuleID] = true
	}
	var out []string
	if byRule["PB101"] || byRule["PB102"] || byRule["PB104"] {
		out = append(out, "run `updpkgsums` to (re)generate strong checksums for the sources")
	}
	if byRule["PB601"] {
		out = append(out, "run `makepkg --printsrcinfo > .SRCINFO` to regenerate .SRCINFO from the PKGBUILD")
	}
	return out
}

// gitTransports are the URL schemes `git ls-remote` may be pointed at. The
// URL comes from an untrusted source=() entry, so everything else is refused:
// notably file:// and ext:: (which git treats as "run this command"), and
// anything without a scheme (which git could read as an option or a local
// path). These cover every transport a real AUR git source uses — makepkg's
// git+ prefix strips to one of them, and scp-style git@host:repo URLs never
// reach here because they parse as local sources.
var gitTransports = map[string]bool{"https": true, "http": true, "git": true, "ssh": true}

// allowedGitURL reports whether url names a remote over an allowed transport.
// Schemes are case-insensitive per RFC 3986; the URL itself is passed to git
// unchanged.
func allowedGitURL(url string) bool {
	scheme, _, ok := strings.Cut(url, "://")
	return ok && gitTransports[strings.ToLower(scheme)]
}

// resolveGitRef resolves a git tag or branch name on a remote to its commit
// hash via `git ls-remote` — the only network access the fix path performs.
func resolveGitRef(rawurl, ref string) (string, error) {
	url := rawurl
	if i := strings.Index(url, "://"); i > 0 {
		if plus := strings.IndexByte(url[:i], '+'); plus >= 0 {
			url = url[plus+1:] // git+https://… → https://…
		}
	}
	if !allowedGitURL(url) {
		return "", fmt.Errorf("refusing to resolve ref over unsupported URL scheme: %q", url)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", url, ref)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0") // never block on credentials
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	var sha string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if strings.HasSuffix(f[1], "^{}") { // peeled commit of an annotated tag
			return f[0], nil
		}
		if sha == "" {
			sha = f[0]
		}
	}
	if sha == "" {
		return "", fmt.Errorf("ref %q not found on %s", ref, url)
	}
	return sha, nil
}

// writeFixed writes data to path, preserving the file's existing permissions.
func writeFixed(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	return os.WriteFile(path, data, mode)
}

// rel shortens path relative to the working directory for display.
func rel(path string) string {
	if wd, err := os.Getwd(); err == nil {
		if r, err := filepath.Rel(wd, path); err == nil && !strings.HasPrefix(r, "..") {
			return r
		}
	}
	return path
}

// editHunk renders a git-style before/after fragment for one edit, computed
// against the original bytes so line numbers stay stable across edits.
func editHunk(orig []byte, e rules.Edit) string {
	ls := e.Start
	for ls > 0 && orig[ls-1] != '\n' {
		ls--
	}
	le := e.End
	if !(le > 0 && le <= len(orig) && orig[le-1] == '\n') {
		for le < len(orig) && orig[le] != '\n' {
			le++
		}
	}
	before := strings.TrimRight(string(orig[ls:le]), "\n")
	after := strings.TrimRight(string(orig[ls:e.Start])+e.New+string(orig[e.End:le]), "\n")
	var b strings.Builder
	for _, l := range strings.Split(before, "\n") {
		if l != "" {
			fmt.Fprintf(&b, "    - %s\n", l)
		}
	}
	for _, l := range strings.Split(after, "\n") {
		if l != "" {
			fmt.Fprintf(&b, "    + %s\n", l)
		}
	}
	return b.String()
}
