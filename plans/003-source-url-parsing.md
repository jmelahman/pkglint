# Plan 003: Correct source-URL parsing — fragment/query order and per-element positions

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**: `git diff --stat 8965fc1..HEAD -- internal/pkgbuild/source.go internal/pkgbuild/pkgbuild.go`
> On any change to those files, compare against the excerpts below before
> proceeding.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED — Step 2 shifts finding line numbers, so golden fixtures change.
- **Depends on**: 001 (tests); ideally after 002 (append) so the two source
  changes land in a sensible order — see the interaction note in Step 2.
- **Category**: correctness (both a false-negative risk on VCS pins and a
  usability bug: findings point at the wrong line)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

Two independent defects in how `source=()` entries are parsed:

1. **Fragment dropped when `?query` precedes `#fragment`** (`parseSourceEntry`).
   The code splits on `?` *before* `#`, despite a comment claiming it "handles
   both orders." For a URL written `…?signed#commit=abc`, the `#commit=abc`
   fragment is swallowed into `Query` and never parsed into the `Fragment` map.
   A rule that checks whether a VCS source is pinned to a commit (reading
   `e.Fragment["commit"]`) then sees *no pin* and can misfire — a false
   negative on exactly the supply-chain property the linter exists to enforce.

2. **Every source entry reports the array's position, not its own**
   (`Sources()`). `e.Pos = v.Pos` assigns the position of the `source=(` token
   to *all* entries, so a finding about the third source points at the first
   line of the array. For a linter whose golden tests "pin down line numbers,"
   this is both a correctness and a UX defect.

## Current state

`internal/pkgbuild/source.go`, `parseSourceEntry` (lines 88–122). The ordering
bug is lines 96–106:

```go
func parseSourceEntry(raw, expanded string) SourceEntry {
	e := SourceEntry{Raw: raw, Expanded: expanded, Fragment: map[string]string{}}
	rest := expanded

	if name, url, ok := strings.Cut(rest, "::"); ok {
		e.Filename = name
		rest = url
	}
	if u, q, ok := strings.Cut(rest, "?"); ok {
		// Fragments come before the query in makepkg URLs; handle both orders.
		e.Query = q
		rest = u
	}
	if u, frag, ok := strings.Cut(rest, "#"); ok {
		rest = u
		if k, v, ok := strings.Cut(frag, "="); ok {
			e.Fragment[k] = v
		}
	}
	e.URL = rest
	// ... scheme/VCS detection on rest ...
}
```

Trace `git+https://x/y.git?signed#commit=abc`: `Cut(rest,"?")` → `rest="git+https://x/y.git"`, `Query="signed#commit=abc"`; then `Cut(rest,"#")` finds no `#` → **`Fragment` stays empty** and `Query` wrongly contains `#commit=abc`.

`Sources()` (source.go:33–53), the position bug is line 46:

```go
func (p *Package) Sources() []SourceEntry {
	var out []SourceEntry
	for name, v := range p.Vars {
		if name != "source" && !strings.HasPrefix(name, "source_") {
			continue
		}
		arch := strings.TrimPrefix(strings.TrimPrefix(name, "source"), "_")
		idx := 0
		for _, raw := range v.Values {
			for _, expanded := range expandBraces(p.Expand(raw)) {
				e := parseSourceEntry(raw, expanded)
				e.Index = idx
				e.Arch = arch
				e.Pos = v.Pos            // <-- array position, identical for every entry
				out = append(out, e)
				idx++
			}
		}
	}
	return out
}
```

`Var.Assign` (pkgbuild.go:25) holds the underlying `*syntax.Assign`. For an
array assignment, `v.Assign.Array.Elems[i].Value.Pos()` is the position of the
i-th written element (before brace expansion). `syntax.Pos` has `.Line()` and
`.Col()` methods; findings ultimately use those via the `finding`/`findingAt`
helpers in `internal/rules`.

## Commands

| Purpose        | Command                                             | Expected |
|----------------|-----------------------------------------------------|----------|
| Build          | `go build ./...`                                    | 0        |
| Vet            | `go vet ./...`                                        | 0        |
| Format         | `test -z "$(gofmt -l .)"`                           | no output|
| Package test   | `go test ./internal/pkgbuild/ ./internal/rules/`    | `ok`     |
| Golden refresh | `go test -run TestGolden -update ./...`             | rewrites goldens |
| Full test      | `go test -race ./...`                               | all pass |

## Scope

**In scope**: `internal/pkgbuild/source.go` (both functions),
`internal/pkgbuild/source_test.go` (cases), and `testdata/*/expected.txt`
(regenerated in Step 3, reviewed by hand).

**Out of scope**: the `Var` struct, rule files, `parseSourceEntry`'s scheme/VCS
detection below `e.URL = rest` (leave it exactly as-is).

## Git workflow

Branch `advisor/003-source-url-parsing`. Two logical commits are fine (one per
step) or one combined. Imperative subject; AI executors add the Co-Authored-By
trailer.

## Steps

### Step 1: Order-independent fragment/query parsing

Replace the two `strings.Cut` blocks (the `?` block and the `#` block, lines
96–106) with logic that splits off `#fragment` and `?query` regardless of order.
The URL ends at the first `#` or `?`; the remainder is some interleaving of one
fragment and one query. Suggested implementation:

```go
	// URL ends at the first '#' (fragment) or '?' (query); makepkg allows
	// either order (…#frag?query or …?query#frag), so parse them positionally.
	tail := ""
	if i := strings.IndexAny(rest, "#?"); i >= 0 {
		tail = rest[i:]
		rest = rest[:i]
	}
	for tail != "" {
		delim := tail[0]
		seg := tail[1:]
		if j := strings.IndexAny(seg, "#?"); j >= 0 {
			tail = seg[j:]
			seg = seg[:j]
		} else {
			tail = ""
		}
		if delim == '#' {
			if k, v, ok := strings.Cut(seg, "="); ok {
				e.Fragment[k] = v
			}
		} else {
			e.Query = seg
		}
	}
	e.URL = rest
```

Keep everything from the scheme detection (`scheme, _, ok := strings.Cut(rest, "://")`)
onward unchanged. Note `e.URL` still excludes both fragment and query, matching
today's behavior (so `Host()` and VCS detection are unaffected).

**Verify**: `go build ./...` → 0.

### Step 2: Per-element positions in `Sources()`

Give each entry the position of its written array element, falling back to the
array position when the element index is out of range (scalar-derived values, or
elements that came from a `+=` append whose `Assign` differs — see plan 002).

```go
		for rawIdx, raw := range v.Values {
			pos := v.Pos
			if v.Assign != nil && v.Assign.Array != nil && rawIdx < len(v.Assign.Array.Elems) {
				if el := v.Assign.Array.Elems[rawIdx]; el.Value != nil {
					pos = el.Value.Pos()
				}
			}
			for _, expanded := range expandBraces(p.Expand(raw)) {
				e := parseSourceEntry(raw, expanded)
				e.Index = idx
				e.Arch = arch
				e.Pos = pos
				out = append(out, e)
				idx++
			}
		}
```

**Interaction with plan 002 (append)**: after 002, a `source+=` merge keeps the
*first* assignment's `Assign`, so appended elements have `rawIdx >=
len(v.Assign.Array.Elems)` and correctly fall back to `v.Pos`. That is the
documented, accepted limitation from 002 — do not try to "fix" it here.

**Note on brace expansion**: `foo{,.sig}` expands to two entries sharing one
written element, so both get that element's position. That is correct — they
occupy the same source line.

**Verify**: `go build ./...` → 0; `go vet ./...` → 0.

### Step 3: Regenerate and review golden fixtures

Step 2 changes the line numbers reported for source-related findings, so the
golden fixtures will change.

1. Run `go test -run TestGolden ./...` first **without** `-update` and confirm
   it now FAILS (proving the fixtures exercise source findings and your change
   took effect). If it still passes, the fixtures have no source findings — note
   that and continue.
2. Run `go test -run TestGolden -update ./...`.
3. `git diff testdata/` and inspect every changed line. Each change must be a
   line/column number moving from the `source=(` line to the actual element's
   line. If any finding *disappears* or its rule ID changes, STOP — that's a
   regression, not a reposition.

**Verify**: after `-update`, `go test -race ./...` → all pass.

### Step 4: Regression tests

In `internal/pkgbuild/source_test.go`, add:

- **Fragment after query**: `parseSourceEntry("git+https://x/y.git?signed#commit=abc", <same>)`
  → `Fragment["commit"]=="abc"` and `Query=="signed"`.
- **Fragment before query** (canonical, must still work):
  `…#commit=abc?signed` → `Fragment["commit"]=="abc"`, `Query=="signed"`.
- **Fragment only** / **query only** → each parsed, the other empty.
- **Positions**: load a PKGBUILD whose `source=(` opens on line N and lists
  three entries on lines N, N+1, N+2 (one per line); assert `Sources()[k].Pos.Line()`
  equals the element's actual line, not N for all three. (Write the fixture so
  each element is on its own line.)

**Verify**: `go test ./internal/pkgbuild/` → `ok`.

### Step 5: Full verification

- `go build ./...` → 0
- `go vet ./...` → 0
- `test -z "$(gofmt -l .)"` → no output
- `go test -race ./...` → all pass

## Test plan

- Unit cases above cover both defects and both fragment/query orders plus the
  canonical order (guard against regressing the common case).
- The golden diff review in Step 3 is the integration check.

## Done criteria

- [ ] `?query#fragment` now populates `Fragment` correctly (test passes)
- [ ] Canonical `#fragment?query` still works (test passes)
- [ ] `Sources()[k].Pos` reflects each element's own line
- [ ] Golden fixtures regenerated; diff is *only* repositioned line/col numbers,
      no findings gained/lost unexpectedly
- [ ] `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all clean
- [ ] `plans/README.md` row for 003 → DONE

## STOP conditions

- Golden diff shows a finding disappearing or a rule ID changing (regression).
- `v.Assign.Array` is nil for an array Var you expected to have elements —
  report it rather than forcing positions.
- Canonical-order fragment parsing breaks (test case regresses) — your tail
  loop mishandles the first delimiter; re-check the `IndexAny` bounds.

## Maintenance notes

- Reviewer: confirm the tail-parsing loop terminates on adversarial input
  (e.g. `a#b#c?d?e`) — it should consume one delimiter per iteration and never
  loop forever. The 001/003 tests should include one such pathological string
  asserting it returns *something* without hanging.
- If plan 002 has NOT landed yet, Step 2 still works (the `rawIdx <
  len(...Elems)` bound simply never triggers the fallback for appended values,
  because there are none). Ordering 002-before-003 is preferred but not
  strictly required.
