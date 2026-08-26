// pkglint is a security-focused linter for Arch Linux PKGBUILDs.
//
// It statically analyzes PKGBUILDs and install scriptlets — never sourcing
// them — and reports integrity, hermeticity, and code-execution findings
// with an overall letter grade per package.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"github.com/jmelahman/pkglint/internal/report"
	"github.com/jmelahman/pkglint/internal/rules"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("pkglint", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "error", "exit non-zero when a finding is at or above this severity (info, warn, error, critical, or never)")
	ignore := fs.String("ignore", "", "comma-separated rule IDs to disable, e.g. PB105,PB206")
	listRules := fs.Bool("rules", false, "print all rules and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: pkglint [flags] [path ...]\n\npaths are package directories or PKGBUILD files (default: .)\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "pkglint", version)
		return 0
	}
	if *listRules {
		for _, r := range rules.Registry() {
			fmt.Fprintf(stdout, "%s %-24s %s\n", r.ID, r.Name, r.Doc)
		}
		return 0
	}

	ignored := map[string]bool{}
	for _, id := range strings.Split(*ignore, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ignored[id] = true
		}
	}

	paths := fs.Args()
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

	switch *format {
	case "json":
		if err := report.RenderJSON(stdout, reports); err != nil {
			fmt.Fprintln(os.Stderr, "pkglint:", err)
			return 2
		}
	case "text":
		report.RenderText(stdout, reports)
	default:
		fmt.Fprintf(os.Stderr, "pkglint: unknown format %q\n", *format)
		return 2
	}

	if *failOn == "never" {
		return 0
	}
	sev, err := rules.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pkglint:", err)
		return 2
	}
	if report.ExceedsThreshold(reports, sev) {
		return 1
	}
	return 0
}
