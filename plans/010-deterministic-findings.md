# Plan 010: Make findings output total-ordered and de-duplicated

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/rules/rules.go internal/rules/scriptlet.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P1 (nondeterminism makes golden tests flaky and reports unstable)
- **Effort**: S
- **Risk**: LOW — output-ordering + dedup only; no rule logic changes.
- **Depends on**: none. Best sequenced BEFORE re-generating any goldens in other
  plans, so their `-update` runs are stable.
- **Category**: correctness (determinism) + report quality
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

Two issues make the finding list unstable:

- **C13 — the sort is not a total order.** `Run` sorts findings by
  `(Path, Line, RuleID)` only, with `sort.Slice` (not stable). Two findings that
  share path+line+rule but differ in column or message tie, and their relative
  order is left to the unstable sort — which is seeded from Go's randomized map
  iteration upstream (`NewContext` ranges `pkg.Vars`; `Sources()` ranges a map).
  So the *same* PKGBUILD can print findings in different orders across runs,
  making `TestGolden` flaky and diffs noisy.

- **C15 — PB502 double-reports.** `checkScriptletPersistence` loops every
  persistence-path hint against each argument with no `break`, and the hint list
  overlaps (`/etc/zsh` and `.zshrc`, etc.), so a single argument like
  `/etc/zsh/.zshrc` yields two identical PB502 findings. The redirect loop has
  the same shape. Duplicates inflate the finding count and clutter the report.

Fixing both in `Run` (total comparator + drop exact duplicates) solves the
general class: any rule that emits an exact-duplicate finding is de-duplicated,
and the order becomes fully determined regardless of upstream map iteration.

## Current state

`internal/rules/rules.go`, `Run` (lines 295–305):

```go
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
	return out
```

`Finding` (rules.go:43–50) has `RuleID, Severity, Message, Path, Line, Col`.

`internal/rules/scriptlet.go`, the over-generating loops (86–93 and 104–109):

```go
		for _, a := range c.Args {
			for _, hint := range persistencePathHints {
				if strings.Contains(a, hint) {
					out = append(out, c.finding("PB502", Error,
						"scriptlet touches %q, a persistence location outside pacman's tracking", a))
				}
			}
		}
```

## Commands

| Purpose      | Command                                   | Expected |
|--------------|-------------------------------------------|----------|
| Build        | `go build ./...`                          | 0        |
| Vet          | `go vet ./...`                              | 0        |
| Format       | `test -z "$(gofmt -l .)"`                 | no output|
| Rules tests  | `go test ./internal/rules/`               | `ok`     |
| Determinism  | `go test -count=20 ./internal/rules/`     | stable, all pass |
| Golden       | `go test -run TestGolden ./...`           | see Step 3 |
| Full         | `go test -race ./...`                     | all pass |

## Scope

**In scope**: `internal/rules/rules.go` (`Run`'s comparator + a dedup pass).
Optionally `internal/rules/scriptlet.go` (add `break`s) as a complementary
narrowing. Tests.
**Out of scope**: the fix-path ordering (`ApplyEdits` already sorts and drops
overlaps); other rules' logic.

## Git workflow

Branch `advisor/010-deterministic-findings`. Imperative subject; AI executors
add the Co-Authored-By trailer.

## Steps

### Step 1: Total comparator + dedup in `Run`

Replace the sort with a total order (add `Col`, then `Message` as final
tiebreakers), then drop exact-duplicate adjacent findings:

```go
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Message < b.Message
	})
	// Drop exact duplicates (same rule + location + message). After a total
	// sort, duplicates are adjacent. This de-noises rules that can emit the
	// same finding twice (e.g. overlapping persistence-path hints).
	if len(out) > 1 {
		deduped := out[:1]
		for _, f := range out[1:] {
			last := deduped[len(deduped)-1]
			if f.RuleID == last.RuleID && f.Path == last.Path && f.Line == last.Line &&
				f.Col == last.Col && f.Message == last.Message {
				continue
			}
			deduped = append(deduped, f)
		}
		out = deduped
	}
	return out
```

Two findings identical in all those fields are indistinguishable to a user, so
dropping the extra is safe. `Severity` is not in the key: an exact-location,
exact-message pair with differing severity shouldn't occur from one rule, and if
it did, keeping the first is acceptable — but if you prefer, include `Severity`
in the equality check to be conservative (it won't change observed behavior).

**Verify**: `go build ./...` → 0.

### Step 2 (optional but recommended): stop PB502 over-generating at the source

Add a `break` after the first matching hint in both loops in `scriptlet.go`, so
a single argument yields at most one finding even before the `Run` dedup:

```go
		for _, a := range c.Args {
			for _, hint := range persistencePathHints {
				if strings.Contains(a, hint) {
					out = append(out, c.finding("PB502", Error,
						"scriptlet touches %q, a persistence location outside pacman's tracking", a))
					break
				}
			}
		}
```

Do the same in the redirect loop (104–109). This is defense-in-depth; the `Run`
dedup already collapses the duplicates, but not emitting them is cleaner.

**Verify**: `go build ./...` → 0; `go vet ./...` → 0.

### Step 3: Tests

- **Determinism**: add a test that runs `rules.Run` on a fixed PKGBUILD (one
  that yields several findings sharing a line, e.g. multiple sources on one line
  or multiple rules at one location) N times and asserts the finding slice is
  identical every time (`reflect.DeepEqual` across runs). Run the suite with
  `go test -count=20 ./internal/rules/` and confirm no flake.
- **Dedup**: a scriptlet argument like `/etc/zsh/.zshrc` (matches both `/etc/zsh`
  and `.zshrc`) yields exactly **one** PB502 finding, not two. Assert
  `ruleIDs(...)["PB502"] == 1` for that single construct.
- **No over-dedup**: two genuinely different findings at the same location
  (different rule IDs, or different messages) are BOTH retained.

**Verify**: `go test -count=20 ./internal/rules/` → all pass, stable.

### Step 4: Golden + full verification

- The total order may reorder some golden lines (previously unstable ties now
  fixed) and drop any duplicate PB502 lines. Run `go test -run TestGolden ./...`;
  if it fails, `git diff testdata/` should show only (a) reordered lines and
  (b) removed duplicate findings — never a *unique* finding disappearing. STOP
  if a distinct finding is lost. Then `go test -run TestGolden -update ./...` and
  re-review.
- `go build`, `go vet`, `gofmt -l`, `go test -race ./...` → all clean.

## Test plan

- Determinism via `-count=20` (the flakiness proof), dedup count assertion, and
  the no-over-dedup guard.

## Done criteria

- [ ] `Run` uses a total order (Path, Line, Col, RuleID, Message)
- [ ] Exact-duplicate findings are dropped
- [ ] `/etc/zsh/.zshrc` yields one PB502, not two
- [ ] `go test -count=20 ./internal/rules/` is stable
- [ ] Golden diff is only reorders + removed duplicates (no unique finding lost)
- [ ] `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all clean
- [ ] `plans/README.md` row for 010 → DONE

## STOP conditions

- A golden diff removes a *unique* finding (over-dedup) — your equality key is
  too loose; include more fields or investigate.
- `-count=20` still flakes — there is another nondeterminism source (e.g. a
  finding whose Message embeds a map-ordered list); find and stabilize it, or
  report.

## Maintenance notes

- This plan makes every other plan's `-update` golden runs reproducible, so
  landing it early reduces churn. If sequenced after plans that already touched
  goldens, just re-run their golden checks — order should now be stable.
- Consider (follow-up) trimming the overlapping entries in `persistencePathHints`
  so the hint set is minimal; not required once dedup + `break` are in place.
