# pkglint

Never execute anything from analyzed input: PKGBUILDs are parsed (mvdan.cc/sh),
package archives are parsed (debug/elf) — no sourcing, no `ldd`, no interpreters.
This holds absolutely for every analysis path — `lint`, `--fix`, `--add-ignores`,
all of `internal/`. The single exception is `pkglint build` (`build.go`), which
runs makepkg because that is the only way to get the artifact the PB8xx rules
inspect: a separately named verb `pkglint <path>` never reaches, gated on the
static findings, and confined to the `runCmd`/`lookPath` seams. Do not grow a
second one.

The gate is the whole justification, so nothing in the analyzed input may weaken
it: it reads the findings with the file's own `# pkglint: ignore=` directives
disregarded, a file argument must be the `PKGBUILD` makepkg will actually build,
and makepkg's `-p`/`-D` are refused. A new way to reach `runCmd` has to answer
"could a PKGBUILD talk its way through this?" first.

(`--fix` does start `git ls-remote` to resolve a VCS ref — a subprocess, not the
input: the URL passes `allowedGitURL`'s scheme allowlist, which exists to keep
git's `ext::` "run this command" transport out. Keep it that way.)

- `go test . -run TestGolden -update` regenerates `testdata/*/expected.txt`.
- CI enforces a statement-coverage floor (test.yml, `-coverpkg=./...`) and a
  fuzz smoke over the untrusted-input parsers; a crasher found by fuzzing is
  checked in under `*/testdata/fuzz/` as a regression seed. Ratchet the floor
  up as gaps close; never lower it.
- `PKGLINT_SMOKE=1 go test ./internal/pkgfile/ -run Inventory -v` sweeps the host's pacman cache.
- Rule contracts (examples, severity-range pinning) are test-enforced; the failures say what to add.
- `build-constraints.txt`/`pyproject.toml` are for the PyPI wheel only; Go deps live in `go.mod`.

## Report-card site

No generated output lives on master. `.github/workflows/site.yml` rebuilds the
site nightly — or on demand: `gh workflow run site.yml` — and force-pushes the
`site` branch as a single root commit holding `docs/`, which Pages serves from
that branch's `/docs`, beside the `data/state.jsonl` that produced it. Keep it
that way: 48 nightly `docs/` snapshots on master are what made a 2MB source
tree a 157MB clone, and a branch that is always one commit deep cannot repeat
it. `docs/` and `data/` are gitignored so a local run cannot re-add them.

Local preview, with the published state as a starting point:

```shell
curl -sfLo /tmp/state.jsonl https://raw.githubusercontent.com/jmelahman/pkglint/site/data/state.jsonl
go run ./site -maintainer Jamison -since-days 90 -top 500 -budget 200 -state /tmp/state.jsonl -out /tmp/site-preview
```

`state.jsonl` caches findings per base, keyed on LastModified plus a rule
registry fingerprint, so registry changes re-lint the corpus automatically over
a few nightly runs. Changing rule *logic* without changing the registry shape
needs a `stateEpoch` bump in `site/state.go`.
