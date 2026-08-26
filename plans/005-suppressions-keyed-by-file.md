# Plan 005: Key inline suppressions by (file, line), not line alone

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/pkgbuild/pkgbuild.go internal/rules/rules.go internal/rules/fix.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED — changes a public method signature (`Suppressed`) and a struct
  field type; every caller must be updated in lockstep. Mechanical but wide.
- **Depends on**: 001 (characterization tests — they pin `parseSuppressions`'s
  per-line output, which this plan does NOT change).
- **Category**: correctness / security-relevant (a suppression in one file
  silently disables findings on the same line number in a *different* file)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

`# pkglint: ignore=PBxxx` directives are collected into a single map keyed by
**line number only**, shared across the PKGBUILD and every install scriptlet.
So a directive on line 12 of `foo.install` also suppresses that rule on line 12
of the `PKGBUILD`, and vice versa. Line numbers collide constantly between a
PKGBUILD and its scriptlets, so this silently hides real findings. For a
security linter, an *accidental* cross-file suppression is a missed finding the
author never intended to waive — and a *deliberate* one is an evasion primitive
(put an `ignore=PB501` comment on a convenient line of a benign file to silence
a scriptlet finding that lands on the same line number).

## Current state

`internal/pkgbuild/pkgbuild.go`:

- `parseSuppressions` (lines 235–251) returns `map[int]map[string]bool`
  (line → set of rule IDs) for **one file's** bytes. This is correct per-file
  and does NOT change.
- `Load` merges every file's suppressions into one package-level map keyed by
  line (the PKGBUILD's suppressions, then each scriptlet's — the comment at the
  scriptlet loop even says *"line collisions across files are acceptable"*,
  which is exactly the bug).
- `Suppressed(ruleID string, line int)` (lines 255–260) looks up `line` and
  `line-1` in that flat map — no file identity:

```go
func (p *Package) Suppressed(ruleID string, line int) bool {
	for _, l := range []int{line, line - 1} {
		if ids, ok := p.Suppressions[l]; ok && ids[ruleID] {
			return true
		}
	}
	// ...
}
```

Callers pass no path:
- `internal/rules/rules.go:289` — `pkg.Suppressed(f.RuleID, f.Line)` inside
  `Run`. Note `Finding` has a `Path` field already.
- `internal/rules/fix.go:100` — `ctx.Pkg.Suppressed(rule.ID, e.Line)` inside
  `CollectEdits`. `Edit` carries a `Line` but (verify) no path; fixers rewrite
  the PKGBUILD, so the correct path here is the PKGBUILD's path.

## Commands

| Purpose      | Command                                           | Expected |
|--------------|---------------------------------------------------|----------|
| Find callers | `grep -rn 'Suppressed(\|Suppressions\[\|\.Suppressions' --include=*.go` | enumerates every site |
| Build        | `go build ./...`                                  | 0        |
| Vet          | `go vet ./...`                                      | 0        |
| Format       | `test -z "$(gofmt -l .)"`                         | no output|
| Tests        | `go test -race ./...`                             | all pass |
| Golden       | `go test -run TestGolden ./...`                   | passes unchanged (fixtures are single-file) |

## Scope

**In scope**: `internal/pkgbuild/pkgbuild.go` (struct field, `Load`,
`Suppressed`), `internal/rules/rules.go` (the `Run` caller),
`internal/rules/fix.go` (the `CollectEdits` caller), and tests.

**Out of scope**: `parseSuppressions`'s per-line parsing; the `line`/`line-1`
"directive on or above the line" behavior (keep it, now scoped per file).

## Git workflow

Branch `advisor/005-suppressions-per-file`. Imperative subject
(e.g. "Scope inline suppressions to their own file"). AI executors add the
Co-Authored-By trailer.

## Steps

### Step 1: Enumerate every touch point

Run the `grep` from the Commands table. You should find: the field declaration,
the two writes in `Load` (PKGBUILD + scriptlet loop), the `Suppressed` method,
and the two callers (rules.go, fix.go). If grep finds a caller NOT listed in
"Current state," update it too and note it in the PR.

### Step 2: Re-key the map by path

In `pkgbuild.go`, change the `Package.Suppressions` field from
`map[int]map[string]bool` to a per-file structure:

```go
// Suppressions maps a file path to that file's inline `# pkglint: ignore=`
// directives (line number -> suppressed rule IDs). Keying by path keeps a
// directive in one file from suppressing findings in another file that happen
// to share a line number.
Suppressions map[string]map[int]map[string]bool
```

Initialize it where the package is constructed (wherever `Suppressions` is made
today — likely `make(map[...])` in `Load`). Update the two write sites in
`Load` to nest under the file's path:

- PKGBUILD directives → `pkg.Suppressions[<pkgbuild path>] = parseSuppressions(pkgbuildBytes)`
- each scriptlet's directives → `pkg.Suppressions[p] = parseSuppressions(data)`
  (where `p` is the scriptlet path already computed in the loop)

Use the **same** path string you store in findings for that file (the PKGBUILD's
`Path` and the scriptlet's `p`), so lookups match exactly. Verify what string
the PKGBUILD unit's `Path` holds and reuse it verbatim.

### Step 3: Add the path parameter to `Suppressed`

```go
// Suppressed reports whether ruleID is suppressed at path:line by a directive
// on that line or the line above it, within the same file.
func (p *Package) Suppressed(ruleID, path string, line int) bool {
	perLine, ok := p.Suppressions[path]
	if !ok {
		return false
	}
	for _, l := range []int{line, line - 1} {
		if ids, ok := perLine[l]; ok && ids[ruleID] {
			return true
		}
	}
	return false
}
```

### Step 4: Update callers

- `internal/rules/rules.go:289`: `pkg.Suppressed(f.RuleID, f.Path, f.Line)`.
- `internal/rules/fix.go:100`: pass the PKGBUILD path. Fixers operate on the
  PKGBUILD, so use `ctx.Pkg.PKGBUILD.Path` (confirm that field name). If any
  fixer can target a scriptlet, thread that path instead — check whether any
  `Edit` originates from a scriptlet; if not, the PKGBUILD path is correct.

**Verify**: `go build ./...` → 0; `go vet ./...` → 0.

### Step 5: Regression tests

Add tests (rules-level, using the `lint(t, files)` helper in
`internal/rules/rules_test.go`) proving the bleed is gone and same-file
suppression still works:

1. **No cross-file bleed**: a PKGBUILD that trips some rule on line N, plus a
   `foo.install` carrying `# pkglint: ignore=<thatRule>` on line N. Assert the
   PKGBUILD finding is STILL reported (the scriptlet's directive must not
   suppress it). Discover a concrete rule+line by running the linter on a small
   fixture first.
2. **Same-file suppression still works**: put the `# pkglint: ignore=<rule>`
   directive on the offending line *within the PKGBUILD* → finding suppressed.
3. **Scriptlet self-suppression**: a scriptlet finding (e.g. PB501) suppressed
   by a directive in the *same scriptlet* → suppressed; a directive in the
   PKGBUILD on the same line number does NOT suppress it.

**Verify**: `go test ./internal/rules/ ./internal/pkgbuild/` → `ok`.

### Step 6: Golden + full suite

- Golden fixtures are single-file packages, so `go test -run TestGolden ./...`
  should pass WITHOUT `-update`. If it changes, a fixture relied on the buggy
  cross-file behavior — inspect and only update if the new behavior is correct.
- `go build`, `go vet`, `gofmt -l`, `go test -race ./...` → all clean.

## Test plan

- The three cases in Step 5 (cross-file isolation is the load-bearing one).
- Confirm no 001 characterization test asserted the flat-map/cross-file
  behavior (001 was instructed to exclude it). If one does, it's a STOP.

## Done criteria

- [ ] `Suppressions` keyed by path; `Suppressed` takes a path
- [ ] All callers updated (grep from Step 1 returns no old-signature call)
- [ ] Cross-file bleed test passes (PKGBUILD finding survives a scriptlet's
      directive on the same line number)
- [ ] Same-file suppression still works (both directions)
- [ ] Golden unchanged; `go test -race ./...` clean
- [ ] `plans/README.md` row for 005 → DONE

## STOP conditions

- A caller of `Suppressed`/`Suppressions` exists outside the three files listed
  and its correct path is ambiguous — report it rather than guessing.
- The PKGBUILD unit's stored `Path` differs from the `Finding.Path` used for
  PKGBUILD findings (lookups won't match) — reconcile before proceeding.
- A 001 characterization test asserts cross-file suppression — report it.

## Maintenance notes

- After this lands, plan 004's PB503 findings (path = the scriptlet) are
  suppressible by a directive *in that scriptlet* — desirable and consistent.
- The nested map type is a little verbose; a small `type suppressionSet` alias
  is fine if the reviewer prefers, but keep the behavior identical.
