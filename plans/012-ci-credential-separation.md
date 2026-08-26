# Plan 012: Separate untrusted AUR scanning from the credentialed push in the site workflow

> **Executor instructions**: Follow step by step; run every verification command
> and confirm the expected result before moving on. Honor the STOP conditions.
> Update this plan's row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 8965fc1..HEAD -- .github/workflows/site.yml`
> On any change to that file, compare against the excerpt below before proceeding.

## Status

- **Priority**: P2 (defense-in-depth for a scheduled CI job)
- **Effort**: S
- **Risk**: LOW (CI-only; verify by a manual `workflow_dispatch` run)
- **Depends on**: none. Complements plan 011 (which hardens the generator itself).
- **Category**: security (a job that processes attacker-controlled AUR content
  also holds repo write access and a persisted push token)
- **Planned at**: commit `8965fc1`, 2026-08-26

## Why this matters

The nightly `Report card site` workflow runs one job that both:
1. executes `go run ./site …`, which **downloads and parses untrusted AUR
   content** (snapshot tarballs, arbitrary PKGBUILDs), and
2. holds `contents: write` and pushes to the repo.

Its checkout also omits `persist-credentials: false` (the other two workflows
set it), so the `GITHUB_TOKEN` stays in the git config *while the untrusted
scan runs*. If the scanner is ever exploited — a parser bug, or simply hostile
generated output — it does so with a live push credential to the default
branch. The scan step needs the network but no write access; the push step needs
write access but runs no untrusted code. They should be different jobs so the
credential is never co-resident with untrusted processing.

## Current state

`.github/workflows/site.yml` (single job, write + scan together):

```yaml
permissions: {}
concurrency:
  group: report-card-site
  cancel-in-progress: false
jobs:
  regenerate:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v6           # note: no persist-credentials: false
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
      - uses: actions/cache@v4
        with:
          path: .cache
          key: aur-snapshots-${{ github.run_id }}
          restore-keys: aur-snapshots-
      - run: go run ./site -maintainer Jamison -top 500 -out docs   # untrusted AUR fetch+parse
      - name: Commit refreshed site
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add docs
          if git diff --cached --quiet; then
            echo "No changes to the report card."
          else
            git commit -m "Regenerate report card site"
            git push
          fi
```

The `test.yml` and `release.yml` workflows already use
`persist-credentials: false` — this workflow is the outlier.

## Commands

| Purpose        | Command                                            | Expected |
|----------------|----------------------------------------------------|----------|
| Lint YAML      | `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/site.yml'))"` | no error |
| (if available) | `actionlint .github/workflows/site.yml`            | no findings |
| Manual run     | trigger `workflow_dispatch` on a branch and watch it | scan job has no write token; publish job commits |

## Scope

**In scope**: `.github/workflows/site.yml` only.
**Out of scope**: source code; pinning actions by SHA (a separate TODO already
noted in the file — mention but don't do it here unless asked); the generator's
own input hardening (plan 011).

## Git workflow

Branch `advisor/012-ci-credential-separation`. Imperative subject
(e.g. "Split site scan from credentialed push"). AI executors add the
Co-Authored-By trailer.

## Steps

### Step 1: Rewrite `site.yml` as two jobs

Scan (no write, no persisted credential) → upload `docs` artifact → publish
(write, no untrusted code) → download artifact → commit + push.

```yaml
name: Report card site

on:
  schedule:
    - cron: "0 9 * * *" # nightly, ~1am PT
  workflow_dispatch:

permissions: {}

concurrency:
  group: report-card-site
  cancel-in-progress: false

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      # TODO: pin actions by SHA with ratchet before enabling branch protection.
      - uses: actions/checkout@v6
        with:
          persist-credentials: false   # no push token while parsing untrusted AUR content
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
      - uses: actions/cache@v4
        with:
          path: .cache
          key: aur-snapshots-${{ github.run_id }}
          restore-keys: aur-snapshots-
      - run: go run ./site -maintainer Jamison -top 500 -out docs
      - uses: actions/upload-artifact@v6
        with:
          name: report-card-docs
          path: docs
          retention-days: 1
          if-no-files-found: error

  publish:
    needs: scan
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      # TODO: pin actions by SHA with ratchet before enabling branch protection.
      - uses: actions/checkout@v6            # default token persists — needed for git push
      - uses: actions/download-artifact@v6
        with:
          name: report-card-docs
          path: docs
      - name: Commit refreshed site
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add docs
          if git diff --cached --quiet; then
            echo "No changes to the report card."
          else
            git commit -m "Regenerate report card site"
            git push
          fi
```

Key properties to preserve/verify:
- The **scan** job has `contents: read` and `persist-credentials: false` — no
  write token is present while untrusted AUR content is fetched and parsed.
- The **publish** job runs **no** project code and no untrusted content: it only
  downloads the already-generated `docs` and commits it. It keeps the default
  persisted credential (needed for `git push`).
- The cache stays on the scan job (that's where snapshots are fetched).
- `if-no-files-found: error` prevents a silent empty publish if the scan
  produced nothing.

### Step 2: Validate

- Parse the YAML (Commands table). If `actionlint` is available, run it.
- Confirm indentation and that both jobs are under `jobs:`.

### Step 3: Manual verification (recommended, requires repo access)

Trigger the workflow via `workflow_dispatch` on the branch and confirm:
- the `scan` job log shows no write permission (and `git remote` has no
  credential), and
- the `publish` job downloads the artifact and either reports "No changes" or
  commits+pushes as before.

If you cannot trigger CI as the executor, note that Step 3 is deferred to the
maintainer and stop after Step 2.

## Test plan

- YAML validity (Step 2). Behavior parity is verified by the manual dispatch
  (Step 3): the site is regenerated and pushed exactly as before, but the scan
  no longer holds the push credential.

## Done criteria

- [ ] `site.yml` split into `scan` (read, no persisted creds) and `publish`
      (write, no untrusted code) jobs
- [ ] `docs` passed between jobs via artifact; `if-no-files-found: error` set
- [ ] YAML validates (and `actionlint` clean if available)
- [ ] `plans/README.md` row for 012 → DONE

## STOP conditions

- The generator writes outputs outside `docs/` that the old single job relied on
  being committed — the artifact only carries `docs`; confirm nothing else was
  being committed (the old job did `git add docs` only, so this should match).
- Org policy blocks `contents: write` on a `needs:`-gated job — if so, report;
  the separation is still desirable and may need an alternative (e.g. a deploy
  key scoped to `docs`).

## Maintenance notes

- The in-file TODO to pin actions by SHA (supply-chain hardening) still applies
  to both jobs; do it in a dedicated pass with a ratchet tool.
- Pairs with plan 011: even with the credential separated, keep the generator's
  input bounds/name sanitization — layered defense.
