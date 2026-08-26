# Plan 001: Establish a characterization test suite for `internal/pkgbuild`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat 8965fc1..HEAD -- internal/pkgbuild/`
> If any file under `internal/pkgbuild/` changed since this plan was written,
> compare the "Current state" excerpts against the live code before proceeding;
> on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none
- **Category**: tests
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

`internal/pkgbuild` is the parser that every one of pkglint's 44 rules depends
on: `RenderWord` (static word evaluation), `Expand` (variable substitution),
source-array parsing, and inline-suppression parsing. It currently has **zero
test files and 0.0% coverage** (`go test -cover ./internal/pkgbuild/` reports
`[no test files]`). That is dangerous for a linter whose entire value
proposition is "quoting/line-continuation tricks that evade regex scanners
don't work here" — a regression in `RenderWord` shows up as a *silently missing*
finding, not a failing test. This suite is also the safety net that makes the
parser bug-fix plans (002, 003, 005) safe to execute; it must land first.

This plan pins the **correct, stable** behaviors of the package. It deliberately
does NOT assert the known-buggy behaviors that plans 002/003/005 will change
(source `+=` handling, cross-file suppression, `?query`-before-`#fragment`
ordering) — see the explicit exclusions in Scope.

## Current state

Files (all in `internal/pkgbuild/`, no `_test.go` files exist yet):

- `pkgbuild.go` — `RenderWord`/`renderParts` (static word rendering, lines
  271–311), `Expand` (variable substitution, lines 182–200), `parseSuppressions`
  (lines 235–251), `installFiles` (lines 204–226), `extractTopLevel` (lines
  134–166).
- `source.go` — `parseSourceEntry` (lines 49–83), `Sources` (lines 31–47),
  `Checksums`/`SumsFor` (lines 105–129), `Host` (lines 86–98).
- `srcinfo.go` — `ParseSrcInfo` (lines 14–29).

Key contract of `RenderWord` (from its doc comment, `pkgbuild.go:264-270`):

```go
// RenderWord returns an approximate textual form of a word. dynamic is true
// when the word contains constructs whose value cannot be determined
// statically (command substitution, process substitution, arithmetic,
// indirection, or parameter operations). Plain references to unknown
// variables render as "$name" and are not considered dynamic ...
func RenderWord(w *syntax.Word, vars map[string]string) (s string, dynamic bool)
```

`renderParts` writes a NUL byte (`"\x00"`) into the output and sets
`dynamic = true` for command/process substitution, arithmetic, and parameter
operations (`ParamExp` with `Excl`/`Length`/`Index`/`Slice`/`Repl`/`Exp` set).
A plain `$name` renders as the literal `"$name"` and is NOT dynamic.

`Expand` (`pkgbuild.go:182-200`) substitutes `$name`/`${name}` from known
top-level **scalar** vars, up to 5 fixpoint passes, leaving unknown refs as-is.

`parseSourceEntry(raw, expanded string)` splits `[filename::]url[#fragment][?query]`
and returns a `SourceEntry` with `Filename`, `URL`, `Proto`, `VCS`, `Fragment`
(a `map[string]string` like `{"commit": "abc"}`), `Query`, and `Local`.

To parse a bash fragment into a `*syntax.Word` for a `RenderWord` test, use the
same parser the package uses (`pkgbuild.go:54-56`): a `syntax.NewParser(...)`
with `syntax.Variant(syntax.LangBash)`. The simplest route is to go through the
public API — write a tiny PKGBUILD string, call `pkgbuild.Load` on a temp dir,
and assert via `Package.Vars`, `Package.Sources()`, `Package.Scalar()`, and
`Package.Suppressed()`. Prefer that public-API approach over reaching into
unexported helpers, because it exercises the real call path the rules use.

Repo conventions to match (see `internal/rules/rules_test.go`):

- Table-driven subtests via `t.Run(name, func(t *testing.T){...})`.
- Write fixtures into `t.TempDir()` and load with `pkgbuild.Load(dir)` — mirror
  the `lint` helper at `internal/rules/rules_test.go:11-25`.
- Package-external test package is fine (`package pkgbuild` is used by the
  code; use `package pkgbuild` for white-box access to unexported
  `parseSourceEntry`/`parseSuppressions`, OR `package pkgbuild_test` and go
  through the public API — pick `package pkgbuild` so you can test the
  unexported helpers directly).

## Commands you will need

| Purpose        | Command                                  | Expected on success        |
|----------------|------------------------------------------|----------------------------|
| Build          | `go build ./...`                         | exit 0                     |
| Vet            | `go vet ./...`                           | exit 0                     |
| Format check   | `test -z "$(gofmt -l .)"`                | exit 0 (no output)         |
| Test (package) | `go test ./internal/pkgbuild/`           | `ok`, all pass             |
| Coverage       | `go test -cover ./internal/pkgbuild/`    | coverage % printed, > 0    |
| Full test      | `go test -race ./...`                    | all pass                   |

## Scope

**In scope** (the only files you should create/modify):
- `internal/pkgbuild/pkgbuild_test.go` (create)
- `internal/pkgbuild/source_test.go` (create)
- `internal/pkgbuild/srcinfo_test.go` (create) — optional, if time permits

**Out of scope** (do NOT touch):
- Any non-test `.go` file. This plan adds tests only; it changes zero behavior.
- Do NOT write tests that assert the following known-buggy behaviors — they are
  fixed by later plans and asserting the current output here would create
  churn:
  - `source+=(...)` merging with `source=(...)` (plan 002).
  - `?query` appearing before `#fragment` in a URL (plan 003).
  - inline `# pkglint: ignore=` directives that live in an `.install`
    scriptlet vs. the PKGBUILD sharing a line number (plan 005).
  If you find yourself writing an assertion about one of those three, STOP and
  skip that case.

## Git workflow

- Branch: `advisor/001-parser-tests` (the repo commits directly to `master`;
  create a branch anyway so review is clean).
- Commit message style: imperative, capitalized, no conventional-commit prefix
  — match `git log` (e.g. "Add characterization tests for internal/pkgbuild").
  Append the trailer `Co-Authored-By: Claude <noreply@anthropic.com>` if you
  are an AI executor (matches existing history).
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Test `RenderWord`'s static-vs-dynamic contract

Create `internal/pkgbuild/pkgbuild_test.go` (`package pkgbuild`). Because
`RenderWord` takes a `*syntax.Word`, add a small helper that parses a single
word from a bash snippet:

```go
func firstWord(t *testing.T, src string) *syntax.Word {
	t.Helper()
	f, err := newParser().Parse(strings.NewReader(src), "test")
	if err != nil { t.Fatalf("parse %q: %v", src, err) }
	// src is a single command like `x=VALUE`; dig out the assignment value word.
	// Simpler: parse `echo VALUE` and take the first arg.
	...
}
```

Prefer the pragmatic route: parse `echo <expr>` and grab
`call.Args[1]` (the first argument word). Then assert `(rendered, dynamic)`
pairs for a table of cases:

| Input word            | Expected rendered | Expected dynamic |
|-----------------------|-------------------|------------------|
| `hello`               | `hello`           | false            |
| `'single quoted'`     | `single quoted`   | false            |
| `"double $pkgname"`   | `double $pkgname` | false            |
| `$unknownvar`         | `$unknownvar`     | false            |
| `${pkgname}`          | `$pkgname`        | false            |
| `$(id)`               | contains `\x00`   | **true**         |
| `"$(curl x)"`         | contains `\x00`   | **true**         |
| `${x:-default}`       | contains `\x00`   | **true**         |
| `${#pkgname}`         | contains `\x00`   | **true**         |
| `$((1+2))`            | contains `\x00`   | **true**         |

For the `vars` argument, also add one case passing
`map[string]string{"pkgname": "demo"}` and asserting `$pkgname` renders as
`demo` (not `$pkgname`), per `renderParts` lines 298–303.

**Verify**: `go test ./internal/pkgbuild/ -run RenderWord` → `ok`, all cases pass.

### Step 2: Test `Expand` and `Scalar`

Add table cases loading a PKGBUILD via `Load(t.TempDir())` and asserting
`Package.Scalar(name)` / `Package.Expand(s)`:

- `pkgver=1.0` + `pkgver` scalar → `1.0`.
- `_base=foo` + `pkgname=$_base-bar` → `Scalar("pkgname")` == `foo-bar`.
- A self-referential chain that must terminate at the 5-pass cap without
  hanging: `a=$b`, `b=$a` → `Expand("$a")` returns within the call (assert it
  returns *something*, does not hang; the exact value is `$a` or `$b`).
- An unknown reference `$nope` → left as `$nope`.

**Verify**: `go test ./internal/pkgbuild/ -run Expand` → `ok`.

### Step 3: Test `parseSourceEntry` for the well-defined cases

In `internal/pkgbuild/source_test.go` (`package pkgbuild`), table-test
`parseSourceEntry(raw, raw)` (pass the same string for `raw` and `expanded`):

- `https://example.com/foo.tar.gz` → `URL` set, `Proto` == `https`, `VCS` == ``,
  `Local` == false, `Filename` == ``.
- `foo.tar.gz::https://example.com/x.tar.gz` → `Filename` == `foo.tar.gz`,
  `URL` == `https://example.com/x.tar.gz`.
- `git+https://github.com/example/foo.git` → `Proto` == `git+https`,
  `VCS` == `git`.
- `git+https://github.com/example/foo.git#commit=abc123` →
  `Fragment["commit"]` == `abc123`.
- `local-file.patch` (no `://`) → `Local` == true, `Proto` == ``.
- `http://example.com/x.tar.gz` → `Proto` == `http` (used by PB104).

Do NOT add a case where `?` precedes `#` (that ordering is plan 003's fix).
A `#fragment` followed by `?query` (the conventional order, e.g.
`git+https://x/y.git#tag=v1?signed`) is fine to assert: `Fragment["tag"]`==`v1`,
`Query` contains `signed`.

**Verify**: `go test ./internal/pkgbuild/ -run SourceEntry` → `ok`.

### Step 4: Test `Checksums`/`SumsFor` pairing and `parseSuppressions`

- Load a PKGBUILD with `source=(a b)` and
  `sha256sums=('AAAA...' 'BBBB...')`; assert `Checksums("")["sha256"]` has two
  entries and `SumsFor` for index 0 vs index 1 returns the matching sum.
- Load one with `source_x86_64=(a)` + `sha256sums_x86_64=('CCCC...')`; assert
  `Checksums("x86_64")` returns it.
- `parseSuppressions`: a single-file input with `# pkglint: ignore=PB204` on
  line 3 → the returned map has `3` → `{PB204:true}`. A directive with two IDs
  `# pkglint: ignore=PB204,PB206` → both present. (Single file only — do NOT
  test cross-file collisions; that is plan 005.)

**Verify**: `go test ./internal/pkgbuild/` → `ok`; then
`go test -cover ./internal/pkgbuild/` prints a non-zero coverage number
(expect roughly 55–75%).

### Step 5: Full-suite sanity

**Verify**:
- `go build ./...` → exit 0
- `go vet ./...` → exit 0
- `test -z "$(gofmt -l .)"` → no output
- `go test -race ./...` → all pass (no existing test regressed)

## Test plan

- New files: `internal/pkgbuild/pkgbuild_test.go`, `internal/pkgbuild/source_test.go`,
  optionally `internal/pkgbuild/srcinfo_test.go`.
- Structural pattern to follow: `internal/rules/rules_test.go` (the `lint`
  helper's temp-dir + `Load` approach, and `t.Run` subtests).
- Cases: the tables in Steps 1–4 above. Each is a happy-path or contract
  assertion — this plan fixes no bug, it locks down current correct behavior.
- Verification: `go test -race ./...` all pass; `go test -cover ./internal/pkgbuild/`
  reports > 0% (was 0%).

## Done criteria

ALL must hold:

- [ ] `go build ./...` exits 0
- [ ] `go vet ./...` exits 0
- [ ] `test -z "$(gofmt -l .)"` produces no output
- [ ] `go test -race ./...` exits 0
- [ ] `go test -cover ./internal/pkgbuild/` reports coverage > 0% (previously
      `[no test files]`)
- [ ] Only files under `internal/pkgbuild/*_test.go` are added (`git status`
      shows no non-test file modified)
- [ ] `plans/README.md` status row for 001 updated to DONE

## STOP conditions

Stop and report back (do not improvise) if:

- The `internal/pkgbuild/` code doesn't match the "Current state" excerpts
  (drift since this plan was written).
- You cannot cleanly obtain a `*syntax.Word` for `RenderWord` cases after two
  attempts — report the approach you tried; a reviewer will suggest a helper.
- A characterization test you write documents behavior that looks like a bug
  (e.g. `source+=` overwriting) — do NOT "fix" it here and do NOT assert it as
  correct; note it and skip the case (it belongs to plan 002/003/005).

## Maintenance notes

- Plans 002, 003, and 005 will each add regression tests asserting *fixed*
  behavior in this same package; they may edit the tables here. That is
  expected.
- Reviewer should scrutinize that the `RenderWord` dynamic-detection cases
  match the doc contract exactly — that contract is the linter's core
  anti-obfuscation guarantee.
- Deferred: fuzzing `parseSourceEntry`/`RenderWord` is a good follow-up but out
  of scope here.
