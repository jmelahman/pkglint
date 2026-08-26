# Plan 007: Close three hermeticity coverage gaps (PB204 `go get`, PB204 vendor substring, PB205 `export` in functions)

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/rules/hermetic.go internal/rules/rules.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED — Fix C (the `export`-in-functions walk) adds new PB205
  findings; golden fixtures may change if any fixture weakens Go env inside a
  function. Fixes A and B are low risk.
- **Depends on**: none. Independent of 001–006.
- **Category**: correctness / security (three ways to defeat the hermeticity
  rules that pkglint exists to enforce)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

Three independent gaps let a PKGBUILD fetch code or weaken supply-chain checks
without tripping the rule meant to catch it:

- **A — plain `go get` in `build()` escapes PB204.** The build-phase
  implicit-download check allows-lists `build/install/test/run/mod download` but
  omits `get`. A bare `go get ./...` (or `go get some/module`) in `build()`
  downloads modules over the network mid-build and is not flagged.
- **B — any source containing the substring `"vendor"` disables PB204
  entirely.** `goVendored` returns true if *any* source URL contains "vendor"
  anywhere — e.g. `https://github.com/somevendor/proj`. That one substring turns
  off the whole build-phase download check for the package.
- **C — `export GOSUMDB=off` inside a build function escapes PB205.** PB205
  flags Go env weakening (GOSUMDB=off, GOINSECURE, …). It catches top-level
  assignments (via `pkg.Vars`) and command *prefix* assignments
  (`GOSUMDB=off go build`), but a standalone `export GOSUMDB=off` is a
  `*syntax.DeclClause`, which is never collected as a Command — so inside a
  function it is invisible. The `if c.Name == "export" || c.Name == "declare"`
  branch that looks like it handles this is dead code (a `Command` is only ever
  built from a `*syntax.CallExpr`, never a `DeclClause`).

## Current state

`internal/rules/hermetic.go`.

**A** — `checkGoDownloads` second loop (line 369) omits `get`:

```go
	for _, c := range ctx.CommandsNamed("go") {
		if !c.InBuildPhase() || mutable[c.Stmt] {
			continue
		}
		sub := c.Subcommand()
		if sub != "build" && sub != "install" && sub != "test" && sub != "run" && !(sub == "mod" && c.HasArg("download")) {
			continue // <-- `get` falls here and is skipped
		}
		out = append(out, c.finding("PB204", Warn,
			"go %s may download modules during %s(); vendor them or `go mod download` in prepare()", sub, c.Fn))
	}
```

(The first loop, lines 347–360, already flags `go get pkg@latest` and friends
via `mutableGoRef`; the gap is a *pinned* or bare `go get` in `build()`.)

**B** — `goVendored` (lines 320–324):

```go
	for _, e := range ctx.Pkg.Sources() {
		if strings.Contains(strings.ToLower(e.Expanded), "vendor") {
			return true
		}
	}
	return false
```

**C** — `checkGoEnvWeakening` (lines 399–433). The top-level `Vars` loop
(402–408) and the command-prefix loop (409–421) are fine; the `export`/`declare`
branch (422–430) is dead:

```go
	for _, c := range ctx.Commands() {
		for _, as := range c.Call.Assigns { /* GOSUMDB=off go build — OK */ }
		if c.Name == "export" || c.Name == "declare" { // DEAD: export is a DeclClause, never a Command
			for _, a := range c.Args { /* never reached */ }
		}
	}
```

How to reach the missing nodes: `NewContext` (rules.go:102–116) walks
`pkg.Units()`, using `u.Functions[name].Body` (a `*syntax.Stmt`) and
`u.TopLevel`. The same `Units()`/`Functions` shape lets this rule walk function
bodies for `*syntax.DeclClause` nodes. `renderPlain` (used at hermetic.go:416)
and `findingAt` are already available in this package.

## Commands

| Purpose        | Command                                                | Expected |
|----------------|--------------------------------------------------------|----------|
| Confirm AST    | `go doc mvdan.cc/sh/v3/syntax.DeclClause`              | shows `Args []*Assign` (and `Variant *Lit`) |
| Confirm Unit   | `go doc github.com/jmelahman/pkglint/internal/pkgbuild.Unit` | shows `Functions` + a body field |
| Build          | `go build ./...`                                       | 0        |
| Vet            | `go vet ./...`                                           | 0        |
| Format         | `test -z "$(gofmt -l .)"`                              | no output|
| Rules tests    | `go test ./internal/rules/`                            | `ok`     |
| Golden         | `go test -run TestGolden ./...`                        | see Step 4 |
| Full           | `go test -race ./...`                                  | all pass |

## Scope

**In scope**: `internal/rules/hermetic.go` (all three fixes) + tests.
**Out of scope**: the PB201 network-command rule, `mutableGoRef`, and the
top-level/prefix PB205 detection (already correct — do not touch).

## Git workflow

Branch `advisor/007-hermeticity-gaps`. Three logical commits (A, B, C) or one —
your choice. Imperative subjects; AI executors add the Co-Authored-By trailer.

## Steps

### Step 1 — Fix A: flag `go get` in `build()`

Add `get` to the allow-list in the second loop:

```go
		if sub != "build" && sub != "install" && sub != "test" && sub != "run" && sub != "get" && !(sub == "mod" && c.HasArg("download")) {
			continue
		}
```

This flags a build-phase `go get` (bare or pinned) as an implicit download. A
`go get pkg@latest` is still caught once (the first loop sets `mutable[c.Stmt]`,
which this loop skips). `go get` in `prepare()` is intentionally NOT flagged
(`c.InBuildPhase()` gate) — pre-fetching there is the recommended pattern.

**Verify**: `go build ./...` → 0.

### Step 2 — Fix B: match a vendor *archive*, not any "vendor" substring

Replace the `Sources()` loop in `goVendored`:

```go
	for _, e := range ctx.Pkg.Sources() {
		if isVendorArchive(e) {
			return true
		}
	}
	return false
```

Add the helper (add `"path"` to imports if not present):

```go
// isVendorArchive reports whether a source looks like a bundled vendored-deps
// archive (vendor.tar.gz, foo-1.0-vendor.tar.zst, a local "vendor" bundle),
// rather than any URL that merely contains the substring "vendor" (e.g. a
// GitHub org literally named "somevendor"). Only the file-name component is
// considered.
func isVendorArchive(e pkgbuild.SourceEntry) bool {
	name := e.Filename // the `name::url` local name, when present
	if name == "" {
		name = path.Base(e.URL)
	}
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "vendor") ||
		strings.Contains(name, "-vendor.") ||
		strings.Contains(name, "vendor.tar")
}
```

Confirm `SourceEntry` field names (`Filename`, `URL`) via
`go doc github.com/jmelahman/pkglint/internal/pkgbuild.SourceEntry` and adjust
if different. Keep the earlier precise signals in `goVendored` (the
`-mod=vendor` / `go mod vendor|download` checks, lines 308–318) unchanged.

**Verify**: `go build ./...` → 0.

### Step 3 — Fix C: catch `export`/`declare` weakening inside functions

First confirm the AST shape: `go doc mvdan.cc/sh/v3/syntax.DeclClause` should
show `Args []*Assign`. If it does not, STOP (dependency drift).

Add a walk over **function bodies only** (top-level `export GOSUMDB=off` is
already captured by the `pkg.Vars` loop, so walking only functions avoids double
reporting). Append this inside `checkGoEnvWeakening`, before `return out`:

```go
	// `export`/`declare`/`local`/`readonly` are DeclClause nodes, never
	// CallExpr, so they never reach ctx.Commands(). Walk function bodies for
	// them. Top-level ones are already handled via ctx.Pkg.Vars above.
	for _, u := range ctx.Pkg.Units() {
		for _, fn := range u.Functions { // fn.Body is *syntax.Stmt (as in NewContext)
			syntax.Walk(fn.Body, func(n syntax.Node) bool {
				decl, ok := n.(*syntax.DeclClause)
				if !ok {
					return true
				}
				for _, as := range decl.Args {
					if as.Name == nil {
						continue
					}
					val := ""
					if as.Value != nil {
						val, _ = renderPlain(as.Value)
					}
					if msg, isBad := bad(as.Name.Value, val); isBad {
						out = append(out, findingAt("PB205", Warn, u.Path, as.Pos(), "%s", msg))
					}
				}
				return true
			})
		}
	}
```

Adjust `fn.Body` / `u.Functions` to the exact field names reported by
`go doc ...pkgbuild.Unit` (match what `NewContext` uses at rules.go:106–111).
You may delete the dead `if c.Name == "export" || c.Name == "declare"` block
(422–430) since it never fires; if you prefer to leave it, that's harmless (it
cannot double-report because it never matches).

**Verify**: `go build ./...` → 0; `go vet ./...` → 0.

### Step 4: Tests + golden

Add rules-level tests (via `lint(t, files)`), each asserting the rule fires now
and still doesn't over-fire:

- **A**: `build() { go get example.com/m; }` (no mutable ref) → PB204.
  `prepare() { go get example.com/m; }` → NO PB204 from the build-phase loop.
  `build() { go get example.com/m@latest; }` → exactly one PB204 (not two).
- **B**: a package whose only "vendor" mention is a source URL like
  `https://github.com/somevendor/proj/archive/v1.tar.gz`, plus a build-phase
  `go build` → PB204 STILL fires (the substring no longer suppresses it). And a
  package with a genuine `source=("vendor.tar.gz")` (or `vendor::<url>`) →
  `goVendored` true → build-phase `go build` NOT flagged.
- **C**: `build() { export GOSUMDB=off; go build; }` → PB205 fires (this is the
  regression that proves the gap is closed). Top-level `export GOSUMDB=off`
  still fires **exactly once** (assert count == 1, guarding against a duplicate
  from the new walk). Bare top-level `GOSUMDB=off` still fires.

Discover exact rule expectations with the `expectRule`/`ruleIDs` helpers in
`internal/rules/rules_test.go`.

Golden: Fixes A and B only *add* findings for constructs unlikely to be in the
clean fixture; the malicious fixture may gain PB204/PB205. Run
`go test -run TestGolden ./...`; if it fails, read `git diff testdata/` — every
change must be a **new** PB204/PB205 finding that is genuinely a hermeticity
problem (a build-phase `go get`, a now-un-suppressed `go build`, or an in-function
`export GOSUMDB=off`). Only `-update` if each added finding is correct; a
*removed* finding is a STOP.

**Verify**: `go test ./internal/rules/` → `ok`.

### Step 5: Full verification

`go build ./...`, `go vet ./...`, `test -z "$(gofmt -l .)"`,
`go test -race ./...` → all clean.

## Test plan

- The three "now fires" cases (A/B/C) are the load-bearing proofs; the "still
  doesn't over-fire" cases guard against regressions and duplicates.
- Fix C's top-level count-==-1 assertion is critical: it proves the new
  function-body walk didn't start double-reporting top-level `export`.

## Done criteria

- [ ] Build-phase `go get` trips PB204 (bare and pinned); prepare-phase does not
- [ ] A source URL merely containing "vendor" no longer disables PB204; a real
      vendor archive still does
- [ ] `export GOSUMDB=off` inside a build function trips PB205; top-level still
      fires exactly once
- [ ] Golden diff is only *added* correct findings (or empty)
- [ ] `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all clean
- [ ] `plans/README.md` row for 007 → DONE

## STOP conditions

- `go doc ...DeclClause` does not show `Args []*Assign` — dependency drift.
- The `Unit`/`Function` body field name differs from what `NewContext` uses and
  you cannot resolve it — report rather than guess.
- A top-level `export GOSUMDB=off` produces **two** PB205 findings after Fix C —
  your walk is also covering top-level; restrict it to function bodies (or
  confirm top-level export is NOT in `pkg.Vars` and instead dedupe).
- Any golden diff shows a finding disappearing.

## Maintenance notes

- Fix B is a heuristic; the reviewer may prefer to drop the source-based vendor
  detection entirely and rely only on the precise `-mod=vendor` / `go mod
  vendor` signals. Either is defensible — the point is that a bare "vendor"
  substring must no longer disable the check. If dropped, re-run the Fix B tests
  (the genuine-vendor-archive case would then rely on the `-mod=vendor` signal
  instead).
- Once plan 010 (dedup in `Run`) lands, the Fix C top-level double-report risk
  is belt-and-suspendered, but do not rely on it here — keep the walk scoped to
  function bodies.
