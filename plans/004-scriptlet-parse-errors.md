# Plan 004: Surface install scriptlets that fail to parse (new rule PB503)

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/pkgbuild/pkgbuild.go internal/rules/scriptlet.go internal/rules/examples.go`
> On any change to those files, compare against the excerpts below first.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none (independent of 001–003; can run any time). Interacts with
  plan 013 (examples-as-tests) — see "Interaction" below.
- **Category**: correctness / security-relevant (an unparseable root-run
  scriptlet is currently analyzed by nothing and the linter stays silent)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

`Load` reads each install scriptlet and parses it. When parsing **fails**, the
current code silently `continue`s — the scriptlet is dropped from
`pkg.Scriptlets`, so **every** scriptlet rule (PB501 network-in-scriptlet, PB502
persistence, plus the PB3xx/PB4xx rules that run over scriptlets) skips it. The
package still gets graded, and the grade reflects a scriptlet nobody looked at.

For a security linter this is the worst kind of false negative: a `.install`
file that runs as root during `pacman -U` but is malformed — or deliberately
obfuscated so `mvdan.cc/sh` can't parse it — produces a **clean report**.
`mvdan.cc/sh` is a very compatible bash parser; a genuine parse failure is rare
and itself a red flag. The linter should say "I could not analyze this
root-executed file," not stay silent.

Note the *missing*-scriptlet case is already handled by a rule (PB107); this
plan closes the sibling gap for scriptlets that are present but unparseable.

## Current state

`internal/pkgbuild/pkgbuild.go`, `Load` (the scriptlet loop, lines 93–107):

```go
	for _, name := range pkg.installFiles() {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			continue // missing scriptlet is reported by a rule
		}
		su, err := parseUnit(p, data, true)
		if err != nil {
			continue      // <-- parse error silently dropped; nothing ever reports it
		}
		pkg.Scriptlets = append(pkg.Scriptlets, su)
		for line, ids := range parseSuppressions(data) {
			pkg.Suppressions[line] = ids // best effort; line collisions across files are acceptable
		}
	}
```

The `Package` struct (lines 39–50) has no place to record a parse failure.

`internal/rules/scriptlet.go` holds `scriptletRules` (lines 15–33) with PB501
and PB502. Findings can be built either with `c.finding(...)` (needs a Command)
or a plain `Finding{...}` literal (as `checkArch` does in correctness.go:543).
Since a parse error has no Command and no AST, use the literal form.

`internal/rules/examples.go` maps each rule ID to a `Bad`/`Good` snippet;
`TestRegistryIsWellFormed` (rules_test.go:73–74) fails the build if any rule
lacks a non-empty `Bad` and `Good`. So a new rule REQUIRES an examples entry.

## Commands

| Purpose        | Command                                  | Expected |
|----------------|------------------------------------------|----------|
| Build          | `go build ./...`                         | 0        |
| Vet            | `go vet ./...`                            | 0        |
| Format         | `test -z "$(gofmt -l .)"`                | no output|
| List rules     | `go run . --rules`                       | includes `PB503` once, no other new dupes |
| Tests          | `go test -race ./...`                    | all pass |
| Golden (check) | `go test -run TestGolden ./...`          | passes WITHOUT -update (no fixture has an unparseable scriptlet) |

## Scope

**In scope**:
- `internal/pkgbuild/pkgbuild.go` — add a `ScriptletError` type + a
  `ScriptletErrors` field to `Package`; record the parse error instead of only
  `continue`.
- `internal/rules/scriptlet.go` — add rule PB503 + its `Check`.
- `internal/rules/examples.go` — add a `"PB503"` examples entry.
- Tests: `internal/rules/rules_test.go` (a PB503 case) or a new
  `internal/rules/scriptlet_test.go`.

**Out of scope**: changing how *parseable* scriptlets are handled; touching
other rules.

## Git workflow

Branch `advisor/004-scriptlet-parse-errors`. Imperative subject
(e.g. "Report unparseable install scriptlets as PB503"). AI executors add the
Co-Authored-By trailer.

## Steps

### Step 1: Record parse failures on the Package

In `pkgbuild.go`, add near the `Package` type:

```go
// ScriptletError records an install scriptlet that was present but could not
// be parsed. Such a file is analyzed by no rule yet still runs as root at
// install time, so it must be surfaced rather than silently skipped.
type ScriptletError struct {
	Path string
	Err  string
}
```

Add a field to `Package`:

```go
	ScriptletErrors []ScriptletError
```

Replace the silent `continue` after `parseUnit`:

```go
		su, err := parseUnit(p, data, true)
		if err != nil {
			pkg.ScriptletErrors = append(pkg.ScriptletErrors, ScriptletError{Path: p, Err: err.Error()})
			continue
		}
```

**Verify**: `go build ./...` → 0.

### Step 2: Add rule PB503

Confirm PB503 is unused first: `go run . --rules | grep PB503` → no output. If
PB503 is already taken, use the next free `PB5xx` ID and adjust everything
below consistently.

In `scriptlet.go`, add to the `scriptletRules` slice:

```go
	{
		ID:   "PB503",
		Name: "unparseable-scriptlet",
		Doc: "An install scriptlet pkglint cannot parse is analyzed by no rule, yet its code " +
			"still runs as root at install time. A parse failure usually means the file is malformed " +
			"or deliberately obfuscated to defeat static analysis; either way it must be reviewed by hand.",
		Check: checkScriptletParseError,
	},
```

Add the check (add `"fmt"` to the imports):

```go
func checkScriptletParseError(ctx *Context) []Finding {
	var out []Finding
	for _, se := range ctx.Pkg.ScriptletErrors {
		out = append(out, Finding{
			RuleID:   "PB503",
			Severity: Error,
			Path:     se.Path,
			Line:     1,
			Col:      1,
			Message:  fmt.Sprintf("install scriptlet could not be parsed and was not analyzed: %s", se.Err),
		})
	}
	return out
}
```

(Severity `Error` → grade D. This is deliberate: an unanalyzable root-run file
is serious. The maintainer may prefer `Warn`; leave a one-line comment noting
the choice so it's easy to revisit.)

**Verify**: `go build ./...` → 0; `go run . --rules | grep -c PB503` → `1`.

### Step 3: Add the examples entry

In `examples.go`, add (keep the map's formatting style):

```go
	"PB503": {
		Bad: `# foo.install with an unterminated function — makepkg still runs it as root:
post_install() {
  echo installing
# (missing closing brace)`,
		Good: `post_install() {
  echo installing
}`,
	},
```

**Verify**: `go test ./internal/rules/ -run TestRegistryIsWellFormed` → `ok`.

### Step 4: Regression test

Add a test (new file `internal/rules/scriptlet_test.go`, or extend
`rules_test.go`) that writes a package whose `.install` file is malformed and
asserts PB503 fires. Mirror the `lint(t, files map[string]string)` helper
(rules_test.go:11) — it writes each map entry into a temp dir and runs the full
rule set. Example shape:

```go
func TestUnparseableScriptletReported(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": pkgbuildWith("", "install=foo.install\n"),
		"foo.install": "post_install() {\n  echo hi\n# no closing brace\n",
	}
	got := ruleIDs(lint(t, files))   // ruleIDs: map[ruleID]count, see rules_test.go
	if got["PB503"] == 0 {
		t.Fatalf("expected PB503 for unparseable scriptlet, got %v", got)
	}
}
```

Confirm the header produced by `pkgbuildWith` declares `install=foo.install`
(or set it in the body arg as shown) so the scriptlet is actually loaded. Also
add the inverse: a *well-formed* `foo.install` produces **no** PB503.

**Verify**: `go test ./internal/rules/ -run Scriptlet` → `ok`.

### Step 5: Golden + full suite

- `go test -run TestGolden ./...` should PASS without `-update` (no existing
  fixture has an unparseable scriptlet, so output is unchanged). If it fails,
  inspect why before running `-update` — a fixture may have a scriptlet the new
  rule now flags; only update if that's correct and intended.
- `go build ./...`, `go vet ./...`, `test -z "$(gofmt -l .)"`,
  `go test -race ./...` → all clean.

## Test plan

- Positive: malformed `.install` → PB503 (Step 4).
- Negative: valid `.install` → no PB503.
- Well-formedness: `TestRegistryIsWellFormed` still green (examples entry).
- Golden: unchanged.

## Done criteria

- [ ] Parse failures recorded in `Package.ScriptletErrors` (no longer a silent
      `continue`)
- [ ] PB503 fires for a malformed scriptlet; does not fire for a valid one
- [ ] `go run . --rules` lists PB503 exactly once
- [ ] `TestRegistryIsWellFormed` passes (examples entry present)
- [ ] Golden fixtures unchanged; `go test -race ./...` clean
- [ ] `plans/README.md` row for 004 → DONE

## STOP conditions

- PB503 already exists in the registry with a different meaning — pick the next
  free ID and adjust, or report back.
- `TestGolden` fails and the cause is NOT an intended new PB503 finding.
- A test elsewhere asserts an exact total rule count (adding PB503 changes it) —
  update that count as part of this change and note it.

## Interaction with plan 013 (examples-as-tests)

Plan 013 lints each rule's `Bad` example and asserts it trips that rule. PB503's
finding originates from a *scriptlet parse failure*, not from a PKGBUILD snippet,
so its `Bad` example (a malformed scriptlet fragment) cannot trip PB503 when fed
as a PKGBUILD body. Plan 013 must list **PB503 in its `knownGaps` allowlist**.
This is already called out in plan 013; if you execute 004 after 013, verify
PB503 is in that allowlist.

## Maintenance notes

- Consider (follow-up) also surfacing scriptlets that parse but reference a
  shell feature the analyzer can't model — out of scope here.
- Reviewer: confirm `Error` (vs `Warn`) is the right severity for the project's
  grading philosophy; it drops an otherwise-clean package to D.
