# pkglint

Never execute anything from analyzed input: PKGBUILDs are parsed (mvdan.cc/sh),
package archives are parsed (debug/elf) — no sourcing, no `ldd`, no interpreters.

- `go test . -run TestGolden -update` regenerates `testdata/*/expected.txt`.
- CI enforces a statement-coverage floor (test.yml, `-coverpkg=./...`) and a
  fuzz smoke over the untrusted-input parsers; a crasher found by fuzzing is
  checked in under `*/testdata/fuzz/` as a regression seed. Ratchet the floor
  up as gaps close; never lower it.
- `PKGLINT_SMOKE=1 go test ./internal/pkgfile/ -run Inventory -v` sweeps the host's pacman cache.
- Rule contracts (examples, severity-range pinning) are test-enforced; the failures say what to add.
- `build-constraints.txt`/`pyproject.toml` are for the PyPI wheel only; Go deps live in `go.mod`.

## Report-card site

`docs/` is generated output — never hand-edit. `.github/workflows/site.yml`
rebuilds and commits it nightly, or on demand: `gh workflow run site.yml`.
Local preview: `go run ./site -maintainer Jamison -since-days 90 -top 500 -budget 200 -state data/state.jsonl -out /tmp/site-preview`.

`data/state.jsonl` caches findings per base, keyed on LastModified plus a rule
registry fingerprint, so registry changes re-lint the corpus automatically over
a few nightly runs. Changing rule *logic* without changing the registry shape
needs a `stateEpoch` bump in `site/state.go`.
