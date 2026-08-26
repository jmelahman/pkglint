# Plan 009: Sanitize terminal output; fix "." package name and null findings

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/report/report.go main.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P2 (SEC5 is real but low-severity; C14 items are UX/consumer
  correctness)
- **Effort**: S
- **Risk**: LOW.
- **Depends on**: none.
- **Category**: security (terminal-injection) + correctness (report naming and
  JSON shape)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

Three defects in how results are rendered:

- **SEC5 — terminal injection via untrusted content.** `RenderText` writes
  `r.Name`, `r.Err`, `f.Path`, and `f.Message` to the terminal verbatim. Those
  strings are derived from the untrusted PKGBUILD (source URLs, `chmod` mode
  args, command names, scriptlet paths). A crafted PKGBUILD can embed ANSI
  escape sequences or carriage returns so the printed report spoofs output,
  hides findings, or garbles the terminal — pkglint is meant to be pointed at
  hostile packages, so this is exactly the threat model. (`RenderJSON` is already
  safe: `encoding/json` escapes control characters.)

- **C14a — `pkglint .` reports the package name as ".".** `report.New` derives
  the name with `filepath.Base(path)`, and its fallback for `"."` calls
  `filepath.Dir(".")` which is again `"."` — so the fix doesn't fix it. The
  report header reads `.: grade …` instead of the directory's name. Same for a
  bare `pkglint PKGBUILD` (in the cwd), which resolves to ".".

- **C14b — errored packages serialize `"findings": null`.** The load-error path
  in `main.go` builds a `PackageReport` without setting `Findings`, so JSON
  consumers see `null` for failed packages while successful ones get `[]`.
  Inconsistent shape breaks naive consumers.

## Current state

`internal/report/report.go`:

```go
// RenderText — writes untrusted fields verbatim (lines 64–83):
func RenderText(w io.Writer, reports []PackageReport) {
	for i, r := range reports {
		// ...
		if r.Err != "" {
			fmt.Fprintf(w, "%s: error: %s\n", r.Name, r.Err)       // r.Name, r.Err raw
			continue
		}
		fmt.Fprintf(w, "%s: grade %s", r.Name, r.Grade)
		// ...
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  %s:%d:%d: %s [%s] %s\n", f.Path, f.Line, f.Col, f.Severity, f.RuleID, f.Message) // f.Path, f.Message raw
		}
	}
}

// New — the "." fallback that doesn't help (lines 51–61):
func New(path string, findings []rules.Finding) PackageReport {
	if findings == nil {
		findings = []rules.Finding{}
	}
	name := filepath.Base(path)
	if name == "PKGBUILD" || name == "." || name == string(filepath.Separator) {
		name = filepath.Base(filepath.Dir(path)) // Dir(".") == "." → still "."
	}
	return PackageReport{Name: name, Path: path, Grade: Grade(findings), Findings: findings}
}
```

`main.go`, the load-error path (line 120):

```go
	reports = append(reports, report.PackageReport{Name: path, Path: path, Grade: "?", Err: err.Error()}) // Findings nil → JSON null
```

## Commands

| Purpose      | Command                                   | Expected |
|--------------|-------------------------------------------|----------|
| Build        | `go build ./...`                          | 0        |
| Vet          | `go vet ./...`                              | 0        |
| Format       | `test -z "$(gofmt -l .)"`                 | no output|
| Report tests | `go test ./internal/report/`             | `ok`     |
| Full         | `go test -race ./...`                     | all pass |
| Golden       | `go test -run TestGolden ./...`           | see Step 4 |

## Scope

**In scope**: `internal/report/report.go` (sanitizer + `New` + a `NewError`
constructor), `main.go` (error path), tests.
**Out of scope**: `RenderJSON` (already safe), the SARIF renderer (plan 014),
grading logic.

## Git workflow

Branch `advisor/009-report-output-safety`. Imperative subject; AI executors add
the Co-Authored-By trailer.

## Steps

### Step 1: Add a control-character sanitizer

In `report.go` (add `"unicode"` and keep `"fmt"`/`"strings"` imports):

```go
// sanitize renders untrusted text safe for a terminal by escaping control
// characters, so PKGBUILD-derived content (paths, messages) cannot inject ANSI
// escapes, carriage returns, or title-setting sequences into the report.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.IsControl(r): // C1 controls (U+0080–U+009F), etc.
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
```

Apply it in `RenderText` to every untrusted field — `r.Name`, `r.Err`, `f.Path`,
`f.Message`:

```go
			fmt.Fprintf(w, "%s: error: %s\n", sanitize(r.Name), sanitize(r.Err))
	// ...
			fmt.Fprintf(w, "%s: grade %s", sanitize(r.Name), r.Grade)
	// ...
			fmt.Fprintf(w, "  %s:%d:%d: %s [%s] %s\n",
				sanitize(f.Path), f.Line, f.Col, f.Severity, f.RuleID, sanitize(f.Message))
```

Leave `f.Severity`, `f.RuleID`, and `r.Grade` unsanitized (registry/enum values,
trusted).

**Verify**: `go build ./...` → 0.

### Step 2: Fix the "." package name

Replace `New`'s name derivation so it resolves through an absolute path when the
base is "."/separator/empty, and still maps a `PKGBUILD` file to its directory:

```go
	name := filepath.Base(path)
	if name == "PKGBUILD" {
		name = filepath.Base(filepath.Dir(path))
	}
	if name == "." || name == string(filepath.Separator) || name == "" {
		if abs, err := filepath.Abs(path); err == nil {
			target := abs
			if filepath.Base(abs) == "PKGBUILD" {
				target = filepath.Dir(abs)
			}
			name = filepath.Base(target)
		}
	}
```

This makes `pkglint .`, `pkglint PKGBUILD`, and `pkglint ./` all report the
containing directory's name; `pkglint dir/PKGBUILD` still reports `dir`.

### Step 3: Add `NewError` and use it for the load-error path

In `report.go`:

```go
// NewError builds a report for a package that failed to load. It reuses New's
// name derivation and guarantees a non-nil Findings slice (so JSON emits [] not
// null, consistent with successful reports).
func NewError(path string, loadErr error) PackageReport {
	r := New(path, nil) // empty (non-nil) findings + proper name
	r.Grade = "?"
	r.Err = loadErr.Error()
	return r
}
```

In `main.go`, replace the load-error append (line 120):

```go
			reports = append(reports, report.NewError(path, err))
```

**Verify**: `go build ./...` → 0; `go vet ./...` → 0.

### Step 4: Tests

In `internal/report/report_test.go` (create if absent):

- **sanitize**: `RenderText` of a finding whose `Message` contains
  `"\x1b[31mred\x1b[0m"` and `"a\rb"` produces output with no raw `0x1b`/`0x0d`
  bytes (assert `!strings.ContainsRune(out, 0x1b)` etc., and that the escaped
  form `\x1b` text appears). Same for a `Path` containing an escape.
- **naming**: `New(".", nil).Name` equals `filepath.Base(cwd)` (compute the
  expected via `os.Getwd`); `New("PKGBUILD", nil).Name` likewise resolves to the
  cwd's base, not ".".
- **NewError**: `json.Marshal` of `[]PackageReport{NewError("x", errors.New("boom"))}`
  contains `"findings":[]` and NOT `"findings":null`; `.Name` is not ".".

**Verify**: `go test ./internal/report/` → `ok`.

### Step 5: Golden + full verification

- Golden fixtures are invoked with a directory path whose base name is
  `clean`/`malicious`, so the naming change shouldn't alter them, and the
  fixtures presumably contain no control characters. Run
  `go test -run TestGolden ./...`; if it changes, inspect: a name flipping from
  "." to a real dir name, or a message losing a stray control byte, is correct —
  `-update` only if every change is explained by this plan.
- `go build`, `go vet`, `gofmt -l`, `go test -race ./...` → all clean.

## Test plan

- The sanitize test is the security proof (no raw escape bytes reach output).
- The naming and NewError tests lock in the two correctness fixes.

## Done criteria

- [ ] `RenderText` escapes control chars in Name/Err/Path/Message
- [ ] `pkglint .` and `pkglint PKGBUILD` report the directory name, not "."
- [ ] Errored packages serialize `"findings":[]`, not `null`
- [ ] `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all clean
- [ ] `plans/README.md` row for 009 → DONE

## STOP conditions

- A golden diff shows a *finding* changing (not just a name or an escaped byte).
- `filepath.Abs` behaves unexpectedly in the test sandbox (e.g. returns an
  error) — the naming fallback should degrade gracefully, not panic; verify.

## Maintenance notes

- If a future renderer prints to a file rather than a TTY, sanitization is still
  correct (escaped control chars are unambiguous). Do not gate `sanitize` on
  `isatty` — a redirected report can still be `cat`'d to a terminal later.
- SARIF (plan 014) should rely on JSON encoding for escaping, mirroring
  `RenderJSON`; it does not need `sanitize`.
