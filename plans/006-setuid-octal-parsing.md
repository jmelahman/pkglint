# Plan 006: Detect setuid/setgid modes by parsing octal, not by the leading digit

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/rules/fs.go internal/rules/fix.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW — narrows a false-negative; only adds detections, removes none
  that were correct.
- **Depends on**: none.
- **Category**: security (PB403 setuid/setgid detection is evadable today)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

PB403 flags `chmod`/`install` commands that create setuid/setgid binaries — a
classic privilege-escalation vector in a package. The numeric-mode detector
decides "is this setuid?" by looking at the **first character** of the mode
string, so any octal spelling whose first digit isn't `4`/`2`/`6` slips
through even when the setuid or setgid bit is set:

- `chmod 04755` — leading `0`, first char isn't 4/2/6 → **not flagged**, yet it
  sets setuid (04755 = u+s, 0755).
- `chmod 7755` — first char `7` → **not flagged**, yet 7 = setuid+setgid+sticky.
- `install -m 02755` — same evasion for setgid.

These are ordinary, valid ways to write the mode. A PKGBUILD author (or an
attacker slipping a line into a PKGBUILD) gets a setuid root binary past the
linter by writing a leading zero. The fix is to parse the octal value and test
the setuid/setgid mask (`0o6000`) — the same mask `clearSetuidBits` already uses
to *remove* those bits, so detection and fix become consistent.

## Current state

`internal/rules/fs.go` — the regex (line 181) and the broken guard (line 188):

```go
var setuidModeRe = regexp.MustCompile(`^[0-7]?[4267][0-7]{3}$|^[24][0-7]{3}$`)

func checkSetuid(ctx *Context) []Finding {
	var out []Finding
	for _, c := range ctx.CommandsNamed("chmod") {
		for _, a := range c.Args {
			symbolic := strings.Contains(a, "+s")
			numeric := setuidModeRe.MatchString(a) && (strings.HasPrefix(a, "4") || strings.HasPrefix(a, "2") || strings.HasPrefix(a, "6"))
			if symbolic || numeric {
				out = append(out, c.finding("PB403", Warn, "chmod %s creates a setuid/setgid file", a))
				break
			}
		}
	}
	// install branch uses isSetuidNumeric (below); setcap branch unaffected.
```

The regex matches `04755`/`7755` (the `[0-7]?` prefix / the `[4267]` first
class), but the `HasPrefix("4"|"2"|"6")` conjunct then rejects them because the
string doesn't *start* with those digits. So the regex and the guard disagree,
and the guard wins.

`internal/rules/fix.go` — the same broken logic drives the auto-fix (lines
646–658). `isSetuidNumeric` is the detector; `clearSetuidBits` already does the
correct octal mask:

```go
func isSetuidNumeric(a string) bool {
	return setuidModeRe.MatchString(a) &&
		(strings.HasPrefix(a, "4") || strings.HasPrefix(a, "2") || strings.HasPrefix(a, "6"))
}

func clearSetuidBits(mode string) string {
	v, err := strconv.ParseInt(mode, 8, 32)
	if err != nil {
		return mode
	}
	v &^= 0o6000 // clear setuid and setgid, keep sticky and permission bits
	return fmt.Sprintf("%04o", v)
}
```

Because `isSetuidNumeric` misses `04755`, the fixer never offers to strip the
bit either — the false negative spans both detection and fix.

## Commands

| Purpose      | Command                                       | Expected |
|--------------|-----------------------------------------------|----------|
| Build        | `go build ./...`                              | 0        |
| Vet          | `go vet ./...`                                  | 0        |
| Format       | `test -z "$(gofmt -l .)"`                     | no output|
| Rules tests  | `go test ./internal/rules/`                   | `ok`     |
| Golden       | `go test -run TestGolden ./...`               | see Step 4 |
| Full         | `go test -race ./...`                         | all pass |

## Scope

**In scope**: `internal/rules/fs.go` (`checkSetuid` numeric branch),
`internal/rules/fix.go` (`isSetuidNumeric`), a shared helper, and tests.

**Out of scope**: the symbolic `+s` detection (already correct), the `setcap`
branch, `clearSetuidBits` (already correct), and `install`'s
`installModeArg`/`setuidInstallFix` mechanics beyond calling the new detector.

## Git workflow

Branch `advisor/006-setuid-octal`. Imperative subject
(e.g. "Detect setuid modes by octal value, not leading digit"). AI executors add
the Co-Authored-By trailer.

## Steps

### Step 1: Add a correct shared detector

Add one helper (put it next to `setuidModeRe` in `fs.go`, or in `fix.go` beside
`clearSetuidBits` — pick one home and reference it from both files, since they
share a package):

```go
// setuidNumericMode reports whether a numeric chmod/install mode sets the
// setuid or setgid bit. It parses the octal value and tests the 0o6000 mask
// rather than inspecting the leading digit, so 04755, 2755, and 7755 are all
// caught. Non-octal (symbolic) modes return false and are handled separately.
func setuidNumericMode(mode string) bool {
	v, err := strconv.ParseInt(mode, 8, 32)
	if err != nil {
		return false
	}
	return v&0o6000 != 0
}
```

(`strconv` is already imported in `fix.go`; add it to `fs.go` if the helper
lives there. Confirm no import cycle — both files are `package rules`.)

### Step 2: Use it in `checkSetuid`

Replace the `numeric := ...` line:

```go
			numeric := setuidNumericMode(a)
```

Keep the `symbolic := strings.Contains(a, "+s")` line and the
`if symbolic || numeric` structure exactly as-is.

**Note on over-approximation** (pre-existing, do NOT change here): the loop
tests *every* argument of `chmod`, so a filename that is itself a setuid-looking
octal number (e.g. a file literally named `4755`) would be flagged. The old code
had the identical behavior. Leave it; narrowing to the mode argument only is a
separate concern.

### Step 3: Use it in `isSetuidNumeric`

```go
func isSetuidNumeric(a string) bool {
	return setuidNumericMode(a)
}
```

(Or inline `setuidNumericMode` at the call site and delete `isSetuidNumeric` if
it has a single caller — verify with `grep -rn isSetuidNumeric internal/`.)

You may now delete `setuidModeRe` if nothing else references it
(`grep -rn setuidModeRe internal/`); if other code still uses it, leave it.

**Verify**: `go build ./...` → 0; `go vet ./...` → 0.

### Step 4: Regression tests + golden

Add table-driven tests (in `internal/rules/fs_test.go` if it exists, else a new
file) covering, via the `lint(t, files)` helper:

- **Now caught**: `chmod 04755`, `chmod 02755`, `chmod 7755`, `chmod 6755`,
  `install -m 04755` → each yields PB403.
- **Still caught (no regression)**: `chmod 4755`, `chmod 2755`, `chmod u+s`.
- **Still NOT flagged**: `chmod 0755`, `chmod 755`, `install -m 0644`,
  `chmod 1777` (sticky only, `0o1000` — mask `0o6000` is 0 → not setuid).
- **Fixer**: a PKGBUILD with `chmod 04755 "$pkgdir/usr/bin/foo"` under
  `--fix`/`--unsafe-fix` (whatever level PB403's fix is) now proposes clearing
  the bit → `04755` becomes `0755` (i.e. `clearSetuidBits("04755")`). Mirror any
  existing PB403 fixer test.

Golden: `chmod 4755` (if present in fixtures) was already flagged, so no change
there. A leading-zero mode is unlikely in fixtures. Run
`go test -run TestGolden ./...`; if it fails, inspect the diff — a fixture may
contain a now-newly-caught mode, which is a correct gain; only `-update` if the
new findings are right.

**Verify**: `go test ./internal/rules/` → `ok`.

### Step 5: Full verification

`go build ./...`, `go vet ./...`, `test -z "$(gofmt -l .)"`,
`go test -race ./...` → all clean.

## Test plan

- The "now caught" table is the proof the evasion is closed; the "still NOT
  flagged" table guards against over-flagging plain modes.

## Done criteria

- [ ] `chmod 04755`/`02755`/`7755` and `install -m 04755` now trip PB403
- [ ] `chmod 0755`/`755`/`1777` still do NOT trip PB403
- [ ] PB403 auto-fix strips the bit for a leading-zero mode
- [ ] Detection and fix share one octal-mask helper
- [ ] `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all clean
- [ ] `plans/README.md` row for 006 → DONE

## STOP conditions

- Removing `setuidModeRe` breaks a build (another reference exists) — keep it.
- A golden diff shows a PB403 finding *disappearing* — that's a regression, not
  the intended gain; investigate before updating.

## Maintenance notes

- Follow-up (out of scope): restrict `checkSetuid`'s chmod loop to the actual
  mode argument (first non-flag arg) so a numerically-named file can't false-
  positive. Low value; note it and move on.
