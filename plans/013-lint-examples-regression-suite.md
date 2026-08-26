# Plan 013: Turn each rule's Bad/Good example into a regression test (DIRECTION-03)

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/rules/examples.go internal/rules/rules_test.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P2 (test-only; no shipped behavior change)
- **Effort**: M — mostly classification work: deciding which examples round-trip
  and which are documentation-only.
- **Risk**: LOW (adds tests; touches no rule logic). May *surface* real
  mismatches between an example and its rule — those are findings to report, not
  silently paper over.
- **Depends on**: none, but if plan 004 (PB503) has landed, PB503 belongs in the
  `knownGaps` allowlist (its example is a malformed scriptlet, not a PKGBUILD).
- **Category**: test coverage / documentation-accuracy (the site shows these
  examples as "this is what the rule catches" — nothing currently proves that)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

Every rule ships a `Bad`/`Good` example (rendered on the report-card site as
"pkglint flags this / prefer this"). Today `TestRegistryIsWellFormed` only checks
they are **non-empty** — nothing verifies the `Bad` snippet actually trips the
rule or that the `Good` one doesn't. So an example can drift from the rule's real
behavior (or be wrong from day one), and the site would confidently show a
misleading example. This plan makes the examples executable: `Bad` must trip its
rule, `Good` must not. It doubles as a regression suite — editing a rule or an
example that breaks the correspondence fails CI.

## Current state

`internal/rules/examples.go` — examples are **PKGBUILD fragments**, not complete
PKGBUILDs, and they come in three shapes:

1. **Top-level assignments** (most PB1xx): e.g. PB104
   `source=("http://example.com/foo-$pkgver.tar.gz")`.
2. **Function bodies / bare commands** (PB2xx/PB4xx): e.g. a `build() { … }` or a
   `chmod`/`install` line.
3. **Scriptlet bodies** (PB5xx): `post_install() { … }` — these only trip their
   rule when analyzed as an **install scriptlet** (`c.Unit.Scriptlet`), i.e.
   written to a `*.install` file referenced by `install=`, NOT inlined in the
   PKGBUILD.

A few are **documentation-only** and can't round-trip as-is (e.g. PB107's Bad is
`install="foo.install"  # …but no foo.install is committed` — the point is a
*missing* file; PB503 from plan 004 is a deliberately unparseable scriptlet).

Test helpers already exist (`internal/rules/rules_test.go`): `lint(t, files)`
(writes files to a temp dir, `Load`s, runs all rules), `ruleIDs(findings)`
(→ `map[ruleID]count`), and a clean full PKGBUILD `cleanPKGBUILD`.

## Commands

| Purpose      | Command                                   | Expected |
|--------------|-------------------------------------------|----------|
| Build        | `go build ./...`                          | 0        |
| The new test | `go test ./internal/rules/ -run Examples -v` | pass (after classification) |
| Full         | `go test -race ./...`                     | all pass |

## Scope

**In scope**: a new test file `internal/rules/examples_test.go`; possibly small
corrections to `examples.go` **only where an example is genuinely wrong** (and
only with the maintainer's confirmation — see STOP conditions).
**Out of scope**: rule logic; the site renderer.

## Git workflow

Branch `advisor/013-example-regression-suite`. Imperative subject; AI executors
add the Co-Authored-By trailer.

## Steps

### Step 1: Build the wrapping + routing harness

In `examples_test.go`, construct a lintable package from a snippet. Use a
minimal header that sets identity fields **but not** the fields examples
commonly set (no `source`/`url`/`sha256sums`/`install`/`DLAGENTS`), so the
snippet's own assignments aren't shadowed:

```go
const exampleHeader = `pkgname=demo
pkgver=1.0.0
pkgrel=1
pkgdesc='demo'
arch=('x86_64')
license=('MIT')
`

// scriptletHint matches snippets that are install-scriptlet bodies; those must
// be linted as a *.install file, not inlined in the PKGBUILD.
var scriptletHint = regexp.MustCompile(`(?m)^\s*(post_|pre_)(install|upgrade|remove)\s*\(\)`)

// packageFor turns one example snippet into the files of a lintable package.
func packageFor(snippet string) map[string]string {
	if scriptletHint.MatchString(snippet) {
		return map[string]string{
			"PKGBUILD":    exampleHeader + "install=demo.install\n",
			"demo.install": snippet,
		}
	}
	return map[string]string{"PKGBUILD": exampleHeader + snippet + "\n"}
}
```

Confirm `scriptletHint` matches the actual PB5xx snippets (read them); adjust the
pattern if a scriptlet example uses a different hook name.

### Step 2: The Bad-trips / Good-doesn't test with an explicit allowlist

```go
// knownGaps lists rules whose example cannot be round-tripped through the
// linter as-is, with the reason. Keep this list SMALL and justified — every
// entry is an example the site shows but this suite does not verify.
var knownGaps = map[string]string{
	"PB107": "Bad depicts a *missing* install file; can't be represented by file content alone",
	// "PB503": "Bad is a deliberately unparseable scriptlet (see plan 004)",
}

func TestExamplesTripTheirRule(t *testing.T) {
	for _, r := range Registry() {
		r := r
		if reason, skip := knownGaps[r.ID]; skip {
			t.Logf("SKIP %s (known gap): %s", r.ID, reason)
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			bad := ruleIDs(lint(t, packageFor(r.Bad)))
			if bad[r.ID] == 0 {
				t.Errorf("%s: Bad example did not trip the rule; got %v", r.ID, bad)
			}
			good := ruleIDs(lint(t, packageFor(r.Good)))
			if good[r.ID] != 0 {
				t.Errorf("%s: Good example still trips the rule (%d)", r.ID, good[r.ID])
			}
		})
	}
}
```

### Step 3: Classify every failure — this is the real work

Run `go test ./internal/rules/ -run Examples -v` and triage each failing rule:

1. **Wrapping issue** — the snippet needs a placement the harness doesn't do
   (e.g. it must be inside `package()` and the rule checks the phase). Extend
   `packageFor` (e.g. wrap bare commands in a `package() { … }` when a rule is
   phase-sensitive), OR add a per-rule wrap override map. Prefer improving the
   harness over enlarging `knownGaps`.
2. **Genuine documentation-only example** — like PB107. Add to `knownGaps` with
   a one-line reason. This is legitimate; keep it rare.
3. **The example is actually wrong** (Bad doesn't demonstrate the rule, or Good
   trips it) — this is a real defect the suite just found. **STOP and report it**
   (see STOP conditions). Only correct `examples.go` if the maintainer confirms
   the intended example; do not silently rewrite documentation to make a test
   pass.
4. **The rule is actually wrong** (Bad legitimately should trip but doesn't; or
   Good legitimately shouldn't but does) — a real rule bug. STOP and report;
   it may warrant its own plan.

Record the disposition of every rule (round-trips / known-gap / example-bug /
rule-bug) in the PR description.

### Step 4: Keep the allowlist honest

Add a guard so `knownGaps` can't silently accumulate rules that actually *do*
round-trip:

```go
func TestKnownGapsAreStillGaps(t *testing.T) {
	for id := range knownGaps {
		r, ok := RuleByID(id)
		if !ok {
			t.Errorf("knownGaps lists unknown rule %s", id)
			continue
		}
		if ruleIDs(lint(t, packageFor(r.Bad)))[id] != 0 {
			t.Errorf("%s is in knownGaps but its Bad example now trips the rule; remove it", id)
		}
	}
}
```

### Step 5: Full verification

`go build ./...`, `go vet ./...`, `test -z "$(gofmt -l .)"`,
`go test -race ./...` → all clean.

## Test plan

- `TestExamplesTripTheirRule` (Bad trips, Good doesn't) across the registry.
- `TestKnownGapsAreStillGaps` prevents the allowlist from hiding regressions.

## Done criteria

- [ ] Every rule not in `knownGaps` has its Bad example trip it and its Good
      example not trip it
- [ ] `knownGaps` is small, each entry justified with a reason
- [ ] `TestKnownGapsAreStillGaps` passes (no stale gaps)
- [ ] Every example-bug or rule-bug found is reported (not silently patched)
- [ ] `go test -race ./...` clean
- [ ] `plans/README.md` row for 013 → DONE

## STOP conditions (important — this suite is a bug-finder)

- A `Bad` example does not trip its rule and the cause is a **wrong example or a
  wrong rule** (not a harness/wrapping limitation) — STOP and report it with the
  rule ID and the observed vs expected findings. Do NOT edit `examples.go` to
  force a pass without maintainer confirmation, and do NOT weaken the assertion.
- A `Good` example trips its own rule — same: report it; it means the
  recommended fix is itself flagged, which is either a doc error or a rule bug.
- `knownGaps` would need more than a handful of entries — that suggests the
  harness (Step 1) is too narrow; improve wrapping before expanding the
  allowlist.

## Maintenance notes

- Once green, this suite makes the site's examples trustworthy and pins them
  against drift. New rules automatically get exercised (they must supply an
  example per `TestRegistryIsWellFormed`, and this suite then verifies it).
- Consider a follow-up that also checks the `--fix` examples: for rules with an
  auto-fix, applying the fix to `Bad` should yield something that no longer
  trips the rule (and ideally matches `Good`). Out of scope here.
