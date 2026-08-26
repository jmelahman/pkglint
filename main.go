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

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"github.com/jmelahman/pkglint/internal/report"
	"github.com/jmelahman/pkglint/internal/rules"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, stdout io.Writer) int {
	var (
		format    string
		failOn    string
		ignore    string
		listRules bool
		doFix     bool
		unsafeFix bool
		diff      bool
		offline   bool
	)

	code := 0
	cmd := &cobra.Command{
		Use:   "pkglint [flags] [path ...]",
		Short: "security-focused linter for Arch Linux PKGBUILDs",
		Long: `pkglint statically analyzes PKGBUILDs and install scriptlets — never
sourcing them — and reports integrity, hermeticity, and code-execution
findings with an overall letter grade per package.

paths are package directories or PKGBUILD files (default: .)`,
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
			if doFix || unsafeFix {
				level := rules.FixSafe
				if unsafeFix {
					level = rules.FixUnsafe
				}
				code = runFix(paths, ignoreSet(ignore), level, diff, offline, stdout)
				return nil
			}
			code = lint(paths, format, failOn, ignore, stdout)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&failOn, "fail-on", "error", "exit non-zero when a finding is at or above this severity (info, warn, error, critical, or never)")
	cmd.Flags().StringVar(&ignore, "ignore", "", "comma-separated rule IDs to disable, e.g. PB105,PB206")
	cmd.Flags().BoolVar(&listRules, "rules", false, "print all rules and exit")
	cmd.Flags().BoolVar(&doFix, "fix", false, "apply safe auto-fixes in place")
	cmd.Flags().BoolVar(&unsafeFix, "unsafe-fix", false, "apply safe and behavior-changing auto-fixes in place (implies --fix)")
	cmd.Flags().BoolVar(&diff, "diff", false, "with --fix/--unsafe-fix: show changes instead of writing them")
	cmd.Flags().BoolVar(&offline, "offline", false, "with --fix: skip fixes needing network access (e.g. resolving VCS refs)")
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
// process exit code.
func lint(paths []string, format, failOn, ignore string, stdout io.Writer) int {
	ignored := ignoreSet(ignore)

	if len(paths) == 0 {
		paths = []string{"."}
	}

	var reports []report.PackageReport
	for _, path := range paths {
		pkg, err := pkgbuild.Load(path)
		if err != nil {
			reports = append(reports, report.PackageReport{Name: path, Path: path, Grade: "?", Err: err.Error()})
			continue
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
	case "text":
		report.RenderText(stdout, reports)
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

// runFix applies auto-fixes at the given level, writing files in place (or,
// with diff, printing the changes it would make). It also nudges toward the
// manual follow-ups for findings that can't be rewritten mechanically.
func runFix(paths []string, ignore map[string]bool, level rules.FixLevel, diff, offline bool, stdout io.Writer) int {
	if len(paths) == 0 {
		paths = []string{"."}
	}
	env := &rules.FixEnv{}
	if !offline {
		env.ResolveRef = resolveGitRef
	}
	rc := 0
	for _, path := range paths {
		pkg, err := pkgbuild.Load(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pkglint: %s: %v\n", path, err)
			rc = 2
			continue
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

// resolveGitRef resolves a git tag or branch name on a remote to its commit
// hash via `git ls-remote` — the only network access the fix path performs.
func resolveGitRef(rawurl, ref string) (string, error) {
	url := rawurl
	if i := strings.Index(url, "://"); i > 0 {
		if plus := strings.IndexByte(url[:i], '+'); plus >= 0 {
			url = url[plus+1:] // git+https://… → https://…
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "ls-remote", url, ref).Output()
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
