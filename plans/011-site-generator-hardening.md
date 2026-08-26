# Plan 011: Harden the site generator — sanitize package names, bound downloads/decompression

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- site/main.go site/render.go`
> On any change to those files, compare against the excerpts below before proceeding.

## Status

- **Priority**: P2 (site generator, not the core linter; but it runs in CI with
  write access — see plan 012)
- **Effort**: S–M
- **Risk**: LOW.
- **Depends on**: none. Complements plan 012 (CI credential separation).
- **Category**: security (path traversal from untrusted package names; disk-fill
  / decompression-bomb from untrusted downloads)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

`site/` scans the **AUR** — attacker-uploadable package bases — and writes a
static site, in CI, with repo write access. Two untrusted-input gaps:

- **SEC4 — package name used as a filesystem path component.** `PackageBase`
  from the AUR metadata is written into output paths unsanitized, at two sites:
  `filepath.Join(out, "badge", r.Name+".svg")` and
  `filepath.Join(out, "package", r.Name+".html")`. A base named `../../evil`
  writes outside the output tree. The AUR's own naming rules make `/` unlikely in
  practice, so this is defense-in-depth against a crafted or compromised metadata
  dump — but the generator must not *assume* upstream validated, especially when
  its output is then `git add`-ed and pushed.

- **SEC6 — unbounded download and decompression.** `download` copies an HTTP
  body to disk with `io.Copy` and no size limit; `loadMeta` decompresses the
  gzip metadata straight into `json.Decode` with no bound. A hostile or
  MITM'd response (or a malicious snapshot) can fill the CI disk or exhaust
  memory (a gzip bomb). (The tarball *extraction* in `extract` is already well
  bounded — per-file `io.LimitReader(tr, maxSnapshotFile)` and a
  `maxSnapshotFiles` count cap — so only the raw download and the metadata
  decode need bounding.)

## Current state

`site/main.go`:

```go
// SEC4 — badge write (line ~124):
for _, r := range results {
	if err := os.WriteFile(filepath.Join(out, "badge", r.Name+".svg"), []byte(badgeSVG(r.Grade)), 0o644); err != nil {
		return err
	}
}

// SEC6 — metadata decode (line ~151):
	gz, err := gzip.NewReader(f)
	// ...
	if err := json.NewDecoder(gz).Decode(&meta); err != nil { // unbounded
		return nil, err
	}

// SEC6 — download (line ~340):
	if _, err := io.Copy(f, resp.Body); err != nil {           // unbounded
		f.Close()
		os.Remove(tmp)
		return err
	}
```

`site/render.go` (line ~77) — the second SEC4 site:

```go
	for _, r := range results {
		data := map[string]any{"R": r, "Rules": ruleIndex}
		if err := renderTo(tmpl, "package.html", filepath.Join(out, "package", r.Name+".html"), data); err != nil {
			return err
		}
	}
```

`r.Name` is the `siteResult.Name`, set from `metaPackage.PackageBase` (untrusted).
`maxSnapshotFile`/`maxSnapshotFiles` constants already exist near the top of
`site/main.go`.

## Commands

| Purpose      | Command                                   | Expected |
|--------------|-------------------------------------------|----------|
| Build        | `go build ./...`                          | 0        |
| Vet          | `go vet ./...`                              | 0        |
| Format       | `test -z "$(gofmt -l .)"`                 | no output|
| Site tests   | `go test ./site/`                         | `ok` (add tests) |
| Full         | `go test -race ./...`                     | all pass |

## Scope

**In scope**: `site/main.go` (name filter + download/decompress bounds),
`site/render.go` (rely on the filtered names), tests under `site/`.
**Out of scope**: the core linter; the `extract` tar bounds (already fine);
CI workflow changes (plan 012).

## Git workflow

Branch `advisor/011-site-hardening`. Imperative subject; AI executors add the
Co-Authored-By trailer.

## Steps

### Step 1 — SEC4: filter unsafe package bases at the single choke point

Add a validator and drop unsafe bases where the seed is selected, so unsafe
names never enter `results` and every downstream use (JSON, links, badge files,
package pages) sees only safe names — keeping filenames and in-page links
consistent.

```go
// safeBase reports whether an AUR package base is safe to use as a single
// path component and URL segment. AUR names are already constrained to this
// shape; anything else (slashes, "..", leading dot, control chars) is treated
// as hostile metadata and dropped.
var baseRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+-]*$`)

func safeBase(name string) bool {
	return name != ".." && baseRe.MatchString(name) && !strings.Contains(name, "..")
}
```

Apply it in `selectSeed` (or immediately after the metadata is loaded), skipping
and logging rejects:

```go
	for _, m := range meta {
		if !safeBase(m.PackageBase) {
			log.Printf("skipping package base with unsafe name %q", m.PackageBase)
			continue
		}
		// ... existing selection logic ...
	}
```

(Confirm the exact loop in `selectSeed`; the point is that no `metaPackage` with
an unsafe `PackageBase` reaches `scanAll`/`results`.) `regexp`, `strings`, and
`log` are already imported in `site/main.go` (verify; add if missing).

**Belt-and-suspenders (optional):** at the two write sites, `continue`+log if
`!safeBase(r.Name)`, in case a name arrives via cached state rather than the
fresh seed.

**Verify**: `go build ./...` → 0.

### Step 2 — SEC6: bound the download

Add a generous ceiling constant (sized to the real metadata dump plus margin —
inspect the actual `packages-meta-ext-v1.json.gz` size and leave headroom) and
cap the copy:

```go
const maxDownloadBytes = 256 << 20 // 256 MiB: a sanity ceiling, not a tight limit

func download(url, path string) error {
	// ...
	limited := io.LimitReader(resp.Body, maxDownloadBytes+1)
	n, err := io.Copy(f, limited)
	if err == nil && n > maxDownloadBytes {
		err = fmt.Errorf("download exceeded %d bytes: %s", maxDownloadBytes, url)
	}
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	// ... existing f.Close()/rename ...
}
```

### Step 3 — SEC6: bound the metadata decompression

Cap the decompressed bytes fed to the JSON decoder (guards against a gzip bomb):

```go
const maxMetaDecompressed = 1 << 30 // 1 GiB decompressed ceiling for the meta dump

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var meta []metaPackage
	if err := json.NewDecoder(io.LimitReader(gz, maxMetaDecompressed)).Decode(&meta); err != nil {
		return nil, err
	}
```

Size `maxMetaDecompressed` above the real decompressed dump (measure it) so
legitimate data is never truncated; a truncated JSON stream will surface as a
decode error, which is the safe failure mode. `io` is already imported.

**Verify**: `go build ./...` → 0; `go vet ./...` → 0.

### Step 4: Tests

Add `site/main_test.go` cases (pure functions, no network):

- **safeBase**: accepts `python-foo`, `a.b+c@1`, `X`; rejects `../../evil`,
  `a/b`, `..`, `.hidden`, `""`, and a name with a control char.
- **download bound** (optional, uses `httptest`): a local server that streams
  more than `maxDownloadBytes` makes `download` return the size error and leave
  no partial file at `path` (the `.tmp` is removed). Keep the limit small in the
  test via a variable if you don't want to move 256 MiB — e.g. make the ceiling
  a package var you can override in the test.
- **meta bound** (optional): feed `loadMeta`-style decode a gzip stream that
  decompresses past a small test ceiling and assert a decode error, not an OOM.

If wiring `httptest` is heavy, at minimum ship the `safeBase` table test; the
download/meta bounds are verified by build + code review.

**Verify**: `go test ./site/` → `ok`.

### Step 5: Full verification

`go build ./...`, `go vet ./...`, `test -z "$(gofmt -l .)"`,
`go test -race ./...` → all clean.

## Test plan

- `safeBase` table is the SEC4 proof; the (optional) httptest bounds are the
  SEC6 proof. Build + review covers the rest.

## Done criteria

- [ ] Unsafe AUR package bases are dropped before scanning; no result name can
      contain `/` or `..`
- [ ] `download` refuses bodies past a ceiling and cleans up the temp file
- [ ] Metadata decompression is bounded before JSON decode
- [ ] `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all clean
- [ ] `plans/README.md` row for 011 → DONE

## STOP conditions

- The real metadata dump is larger than a chosen ceiling (legit truncation) —
  raise the ceiling to fit real data plus margin; the ceilings must never cut
  off valid input.
- `selectSeed`'s structure differs from the excerpt such that a single filter
  point isn't obvious — filter at both the seed and the two write sites and note
  it, rather than leaving a gap.

## Maintenance notes

- These ceilings are DoS backstops, not correctness limits; document the chosen
  values with the measured real sizes so a future maintainer knows the headroom.
- Pair with plan 012: even hardened, the generator parses untrusted AUR content,
  so the credentialed `git push` step should be isolated from the scanning step.
