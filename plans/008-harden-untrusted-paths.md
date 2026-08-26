# Plan 008: Contain `install=` paths and harden `git ls-remote` invocation

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- internal/pkgbuild/pkgbuild.go main.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P1 (Part A — `install=` containment), P2 (Part B — git hardening)
- **Effort**: S
- **Risk**: LOW.
- **Depends on**: none.
- **Category**: security (pkglint processes untrusted PKGBUILDs; today one can
  steer a file read, and the fix path shells out to git with unvalidated input)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

pkglint's entire job is to run against **untrusted** PKGBUILDs (e.g. the site
generator scans the AUR). Two input-trust gaps:

- **A — `install=` steers an arbitrary file read (traversal + DoS).** `Load`
  reads each `install=`-named scriptlet with `filepath.Join(dir, name)` and
  `os.ReadFile`, with no validation of `name`. `install=../../../../etc/passwd`
  makes pkglint read a file outside the package directory; `install=../../../
  ../../dev/zero` makes `os.ReadFile` read an unbounded stream (`/dev/zero`
  never hits EOF) → memory blow-up / hang. (Absolute names like `/etc/shadow`
  are neutralized because `filepath.Join` absorbs the leading slash, but `..`
  traversal is not.) makepkg itself requires an install file to be a plain file
  in the package directory, so anything else is invalid *and* hostile.

- **B — `resolveGitRef` shells out to `git ls-remote` with an unvalidated URL.**
  No scheme allow-list and no `GIT_TERMINAL_PROMPT=0`. A source URL with an
  exotic scheme (`ext::`, `file://`) or a leading `-` is passed straight to git.
  This was assessed as **not clearly exploitable** in the current call paths
  (the URL derives from a `source=` entry and the fix path is opt-in/offline by
  default), so it is retained as cheap defense-in-depth, not a live hole.

## Current state

**A** — `internal/pkgbuild/pkgbuild.go`, `installFiles` `add` closure (207–214):

```go
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
```

and `Load` reads each returned name: `p := filepath.Join(dir, name); data, err := os.ReadFile(p)`.

**B** — `main.go`, `resolveGitRef` (224–256):

```go
func resolveGitRef(rawurl, ref string) (string, error) {
	url := rawurl
	if i := strings.Index(url, "://"); i > 0 {
		if plus := strings.IndexByte(url[:i], '+'); plus >= 0 {
			url = url[plus+1:] // git+https://… → https://…
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "ls-remote", url, ref).Output()
	// ...
}
```

## Commands

| Purpose      | Command                                   | Expected |
|--------------|-------------------------------------------|----------|
| Build        | `go build ./...`                          | 0        |
| Vet          | `go vet ./...`                              | 0        |
| Format       | `test -z "$(gofmt -l .)"`                 | no output|
| Tests        | `go test -race ./...`                     | all pass |
| Golden       | `go test -run TestGolden ./...`           | unchanged |

## Scope

**In scope**: `internal/pkgbuild/pkgbuild.go` (`installFiles` containment);
`main.go` (`resolveGitRef` hardening); tests.
**Out of scope**: changing how scriptlets are parsed once read; the `writeFixed`
symlink behavior (tracked separately — see Maintenance notes).

## Git workflow

Branch `advisor/008-harden-untrusted-paths`. Two commits (A, B) or one.
Imperative subjects; AI executors add the Co-Authored-By trailer.

## Steps

### Step 1 — Part A: contain `install=` names

In `installFiles`, reject anything that isn't a plain filename in the package
directory, *before* it can reach `os.ReadFile`:

```go
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		// An install scriptlet must be a plain file in the package directory.
		// Reject "."/".."; any path separator; and anything whose basename
		// differs from itself (parent traversal, absolute paths) so a hostile
		// install= value cannot steer pkglint into reading files outside the
		// package (traversal) or an unbounded device like /dev/zero (DoS).
		if name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
```

`filepath` and `strings` are already imported. This runs for both the `install=`
var values and the `SrcInfo` `install` values (both funnel through `add`).

**Verify**: `go build ./...` → 0.

### Step 2 — Part A tests

In `internal/pkgbuild/pkgbuild_test.go` (or a rules-level test), add:

- **Traversal rejected**: a package dir containing a real `PKGBUILD` with
  `install=../evil` and a file `../evil` reachable by traversal (create it in a
  parent temp dir). Assert `Load` does NOT read it — i.e. `pkg.installFiles()`
  (or the resulting scriptlet set) excludes it, and no scriptlet content from
  that file appears. The simplest assertion: `install=../../whatever` yields
  zero loaded scriptlets and (after plan 004) NO PB503 for that path.
- **Separator rejected**: `install=sub/dir.install` → not loaded.
- **Plain name still works**: `install=foo.install` with a real `foo.install` in
  the dir → loaded and analyzed as today.

Do NOT reference real system paths (`/etc/passwd`) in tests; use temp-dir
fixtures only.

**Verify**: `go test ./internal/pkgbuild/` → `ok`.

### Step 3 — Part B: harden `resolveGitRef`

After the `git+` stripping, validate the scheme and disable interactive prompts:

```go
	// Only fetch over expected transports; reject exotic schemes (ext::,
	// file://, …) and any leading-dash that git could read as an option.
	switch {
	case strings.HasPrefix(url, "https://"), strings.HasPrefix(url, "http://"),
		strings.HasPrefix(url, "git://"), strings.HasPrefix(url, "ssh://"):
	default:
		return "", fmt.Errorf("refusing to resolve ref over unsupported URL scheme: %q", url)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", url, ref)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0") // never block on credentials
	out, err := cmd.Output()
```

(If AUR VCS sources use additional real schemes — confirm against the VCS
prefixes pkglint already recognizes in `source.go` — add them to the allow-list;
keep `file://`, `ext::`, and anything without `://` rejected. `os` is already
imported in `main.go`.)

**Verify**: `go build ./...` → 0; `go vet ./...` → 0.

### Step 4 — Part B test

`resolveGitRef` performs real network I/O, so unit-test only the **guard**:
calling `resolveGitRef("ext::sh -c whoami", "HEAD")` (and `file:///etc`, and
`-oProxyCommand=...`) returns the scheme-rejection error WITHOUT invoking git.
If `resolveGitRef` is unexported and hard to reach, extract the scheme check
into a tiny testable helper `allowedGitURL(url string) bool` and test that. Do
not add a test that actually reaches the network.

**Verify**: `go test ./...` → `ok` (the new guard test passes offline).

### Step 5: Golden + full verification

- Golden fixtures use plain `install=` names, so `go test -run TestGolden ./...`
  should pass unchanged. If a fixture used a `../` install path to exercise
  something, that was testing the bug — STOP and reconsider.
- `go build`, `go vet`, `gofmt -l`, `go test -race ./...` → all clean.

## Test plan

- Part A: traversal/separator rejected, plain name still loaded (Step 2).
- Part B: scheme guard rejects `ext::`/`file://`/leading-dash offline (Step 4).

## Done criteria

- [ ] `install=../…`, `install=a/b`, `install=..` no longer cause a file read
      outside the package dir
- [ ] Plain `install=foo.install` still loads and is analyzed
- [ ] `resolveGitRef` rejects non-allow-listed URL schemes and sets
      `GIT_TERMINAL_PROMPT=0`
- [ ] Golden unchanged; `go test -race ./...` clean
- [ ] `plans/README.md` row for 008 → DONE

## STOP conditions

- A golden fixture relies on a `../` install path (it was encoding the bug).
- AUR VCS sources legitimately use a scheme you're about to reject — widen the
  allow-list rather than breaking real resolution; if unsure, report.

## Maintenance notes

- Related, tracked separately (not in this plan): `writeFixed` (main.go:259)
  follows symlinks when writing fixes, so a symlinked PKGBUILD could redirect a
  write. Consider `O_NOFOLLOW` / lstat there in a future hardening pass.
- After plan 004 lands, a rejected `install=` name produces no PB503 (the file
  is never read). If desired later, add a dedicated finding for a *suspicious*
  install path (separator/traversal) so the author learns why it was ignored —
  optional, and out of scope here.
