// pkglint is a security-focused linter for Arch Linux PKGBUILDs.
//
// It statically analyzes PKGBUILDs and install scriptlets — never sourcing
// them — and reports integrity, hermeticity, and code-execution findings
// with an overall letter grade per package.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

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
			code = lint(paths, format, failOn, ignore, stdout)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&failOn, "fail-on", "error", "exit non-zero when a finding is at or above this severity (info, warn, error, critical, or never)")
	cmd.Flags().StringVar(&ignore, "ignore", "", "comma-separated rule IDs to disable, e.g. PB105,PB206")
	cmd.Flags().BoolVar(&listRules, "rules", false, "print all rules and exit")
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

// lint runs the rules over each path and renders the reports, returning the
// process exit code.
func lint(paths []string, format, failOn, ignore string, stdout io.Writer) int {
	ignored := map[string]bool{}
	for _, id := range strings.Split(ignore, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ignored[id] = true
		}
	}

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
