# Plan 014: Add SARIF 2.1.0 output (`--format=sarif`) (DIRECTION-02)

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/report/report.go main.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P2 (new capability; additive)
- **Effort**: M
- **Risk**: LOW (new renderer + one `switch` case; existing formats untouched)
- **Depends on**: best AFTER plan 009 (which adds `NewError` and guarantees
  non-nil findings) and plan 010 (deterministic order → stable SARIF). Neither is
  strictly required, but sequencing after them avoids rework.
- **Category**: interoperability (SARIF is the standard consumed by GitHub code
  scanning and other tools)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

pkglint emits `text` and `json` today. SARIF (Static Analysis Results
Interchange Format) is the lingua franca for static-analysis output: uploading a
SARIF file to GitHub code scanning turns pkglint findings into annotations on
PRs and entries in the Security tab. It also lets other tooling ingest results
without parsing pkglint's bespoke JSON. This adds a `--format=sarif` renderer.

## Current state

`main.go`:

```go
cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")   // line 75
// ...
switch format {                                                                   // line 127
case "json":
	if err := report.RenderJSON(stdout, reports); err != nil { /* ... */ }
case "text":
	report.RenderText(stdout, reports)
default:
	fmt.Fprintf(os.Stderr, "pkglint: unknown format %q\n", format)
	return 2
}
```

`internal/rules/rules.go`:

```go
type Severity int
const ( Info Severity = iota; Warn; Error; Critical )   // (paraphrased)
var severityNames = map[Severity]string{Info: "info", Warn: "warn", Error: "error", Critical: "critical"}
```

`internal/report/report.go` — `Finding` fields used per result: `RuleID`,
`Severity`, `Message`, `Path`, `Line`, `Col`. `Registry()` (in `rules`) provides
`{ID, Name, Doc}` for the tool's rule metadata. `RenderJSON` shows the existing
encoder pattern (indented JSON to the writer).

## Commands

| Purpose        | Command                                              | Expected |
|----------------|------------------------------------------------------|----------|
| Build          | `go build ./...`                                     | 0        |
| Vet            | `go vet ./...`                                         | 0        |
| Format         | `test -z "$(gofmt -l .)"`                            | no output|
| Smoke          | `go run . --format=sarif testdata/malicious`         | valid SARIF JSON to stdout |
| JSON validity  | `go run . --format=sarif testdata/malicious \| python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["version"]=="2.1.0"; print(len(d["runs"][0]["results"]),"results")'` | prints a count, no error |
| Report tests   | `go test ./internal/report/`                         | `ok`     |
| Full           | `go test -race ./...`                                | all pass |

## Scope

**In scope**: `internal/report/report.go` (a `RenderSARIF` function + SARIF
structs + a severity→level mapper), `main.go` (a `sarif` case + flag help),
tests.
**Out of scope**: uploading SARIF in CI (a follow-up), the text/json renderers,
grading.

## Git workflow

Branch `advisor/014-sarif-output`. Imperative subject; AI executors add the
Co-Authored-By trailer.

## Steps

### Step 1: SARIF types + severity mapping

In `report.go`, add the minimal SARIF 2.1.0 types and a level mapper. SARIF's
`level` enum is `none|note|warning|error`; map pkglint severities as
Info→`note`, Warn→`warning`, Error→`error`, Critical→`error` (SARIF has no level
above `error`; preserve the distinction in a `properties` bag).

```go
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool        sarifTool           `json:"tool"`
	Results     []sarifResult       `json:"results"`
	Invocations []sarifInvocation   `json:"invocations,omitempty"`
}
type sarifTool struct{ Driver sarifDriver `json:"driver"` }
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}
type sarifText struct{ Text string `json:"text"` }
type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}
type sarifArtifact struct{ URI string `json:"uri"` }
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}
type sarifInvocation struct {
	ExecutionSuccessful       bool               `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}
type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"text"`
}

func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Info:
		return "note"
	case rules.Warn:
		return "warning"
	default: // Error, Critical
		return "error"
	}
}
```

### Step 2: `RenderSARIF`

```go
// RenderSARIF writes findings in SARIF 2.1.0, suitable for GitHub code scanning.
func RenderSARIF(w io.Writer, reports []PackageReport) error {
	reg := rules.Registry()
	idx := make(map[string]int, len(reg))
	driverRules := make([]sarifRule, len(reg))
	for i, r := range reg {
		idx[r.ID] = i
		driverRules[i] = sarifRule{
			ID:               r.ID,
			Name:             r.Name,
			ShortDescription: sarifText{Text: r.Name},
			FullDescription:  sarifText{Text: r.Doc},
		}
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "pkglint",
			InformationURI: "https://github.com/jmelahman/pkglint",
			Rules:          driverRules,
		}},
		Results:     []sarifResult{}, // non-nil → emits [] not null
		Invocations: []sarifInvocation{{ExecutionSuccessful: true}},
	}

	for _, rep := range reports {
		if rep.Err != "" {
			run.Invocations[0].ExecutionSuccessful = false
			run.Invocations[0].ToolExecutionNotifications = append(
				run.Invocations[0].ToolExecutionNotifications,
				sarifNotification{Level: "error", Message: sarifText{Text: rep.Path + ": " + rep.Err}})
			continue
		}
		for _, f := range rep.Findings {
			ri, ok := idx[f.RuleID]
			if !ok {
				ri = -1 // finding from a rule not in the registry (shouldn't happen)
			}
			line := f.Line
			if line < 1 {
				line = 1 // SARIF requires startLine >= 1
			}
			run.Results = append(run.Results, sarifResult{
				RuleID:    f.RuleID,
				RuleIndex: ri,
				Level:     sarifLevel(f.Severity),
				Message:   sarifText{Text: f.Message},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Path},
					Region:           sarifRegion{StartLine: line, StartColumn: f.Col},
				}}},
				Properties: map[string]any{"severity": f.Severity.String()},
			})
		}
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
```

Note: `encoding/json` escapes control characters, so SARIF output needs no extra
sanitization (unlike the text renderer — plan 009). If `f.Path` is an absolute
temp path in some contexts, that's acceptable for a first cut; a follow-up can
make URIs repo-relative for nicer GitHub annotations (see Maintenance notes).

### Step 3: Wire the flag

In `main.go`, add the case and update the flag help:

```go
cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or sarif")
```

```go
	case "sarif":
		if err := report.RenderSARIF(stdout, reports); err != nil {
			fmt.Fprintln(os.Stderr, "pkglint:", err)
			return 2
		}
```

**Verify**: `go build ./...` → 0; the smoke + JSON-validity commands from the
table succeed.

### Step 4: Tests

In `internal/report/report_test.go`:

- **Structure**: `RenderSARIF` over a report with two findings (different
  severities) and one errored report produces JSON where `version=="2.1.0"`,
  `runs[0].tool.driver.name=="pkglint"`, `len(results)==2`, each result's
  `ruleIndex` points at a `driver.rules[i]` whose `id==ruleId`, and the errored
  package appears under `invocations[0].toolExecutionNotifications` with
  `executionSuccessful==false`.
- **Level mapping**: a Critical finding → `"error"`, a Warn → `"warning"`, an
  Info → `"note"`; and its `properties.severity` preserves `"critical"` etc.
- **Non-nil**: a report with zero findings yields `"results": []` (not null).
- Unmarshal the output with `encoding/json` into `map[string]any` (or the sarif
  structs) and assert — do not string-match.

**Verify**: `go test ./internal/report/` → `ok`.

### Step 5: Full verification

`go build ./...`, `go vet ./...`, `test -z "$(gofmt -l .)"`,
`go test -race ./...` → all clean. Existing `text`/`json` golden tests are
unaffected (TestGolden uses the default format).

## Test plan

- Structure + level-mapping + non-nil tests (Step 4); the pipe-to-`python3
  json.load` smoke command proves the output is well-formed JSON with the right
  version.

## Done criteria

- [ ] `--format=sarif` emits valid SARIF 2.1.0 with a populated
      `tool.driver.rules` and correctly-indexed results
- [ ] Severity→level mapping correct; pkglint severity preserved in properties
- [ ] Errored packages surface as tool notifications, `executionSuccessful:false`
- [ ] Empty results serialize as `[]`
- [ ] Flag help lists `sarif`; unknown formats still error
- [ ] `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all clean
- [ ] `plans/README.md` row for 014 → DONE

## STOP conditions

- A finding references a rule ID absent from `Registry()` (`ruleIndex == -1`) —
  investigate; every emitted finding should map to a registered rule.
- The SARIF fails a stricter external validator you have available — reconcile
  against the 2.1.0 schema before finishing.

## Maintenance notes

- Follow-up: make `artifactLocation.uri` repo-relative (strip a leading
  workspace prefix) so GitHub code scanning anchors annotations to files in the
  repo; consider adding `originalUriBaseIds`. Out of scope here.
- Follow-up: a CI step could run `pkglint --format=sarif` over changed PKGBUILDs
  and `upload-sarif`. Natural pairing once this lands.
- If plan 010 has NOT landed, results order may vary run-to-run; SARIF consumers
  usually don't care, but landing 010 first makes output diff-stable.
