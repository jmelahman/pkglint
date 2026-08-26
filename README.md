# pkglint

A security-focused linter for Arch Linux PKGBUILDs.

pkglint statically analyzes PKGBUILDs and their install scriptlets — **without ever
sourcing them** — and reports findings about source integrity, build hermeticity, code
execution, and persistence patterns, condensed into a letter grade per package. It is
built on a real bash AST ([mvdan.cc/sh](https://github.com/mvdan/sh)), so the
quoting/line-continuation tricks that evade regex-based scanners don't work here.

```
$ pkglint ~/pkgbuilds/somepkg
somepkg: grade F, 3 finding(s)
  PKGBUILD:16:3: critical [PB304] a network download is piped straight into bash and executed
  PKGBUILD:11:1: error [PB101] remote source "http://..." has no checksum (SKIP): the download is never verified
  PKGBUILD:24:3: error [PB402] sudo escalates privileges during a build; ...
```

## Install

```shell
go install github.com/jmelahman/pkglint@latest
```

## Usage

```shell
pkglint [flags] [path ...]     # paths are package dirs or PKGBUILD files (default: .)

  --format text|json           # output format
  --fail-on SEVERITY           # exit 1 at or above: info, warn, error (default), critical, never
  --ignore PB105,PB206         # disable rules
  --rules                      # list every rule with its documentation
  --fix                        # apply safe auto-fixes in place
  --unsafe-fix                 # also apply behavior-changing fixes (implies --fix)
  --diff                       # with --fix/--unsafe-fix: show changes instead of writing
  --offline                    # with --fix: skip fixes needing network (e.g. VCS ref resolution)
```

Suppress a reviewed, intentional finding inline:

```bash
# pkglint: ignore=PB204
go build -o "$pkgname" .
```

### Auto-fixing

`--fix` rewrites what it can and prints every change; `--diff` previews without
writing. Fixes come in two tiers:

| Tier | Flag | Rules | What it does |
|------|------|-------|--------------|
| Safe | `--fix` | PB103, PB203, PB205 | Pin a mutable VCS tag/branch to its current commit (via `git ls-remote`); append `--locked` to `cargo`; delete Go verification-disabling env settings |
| Unsafe | `--unsafe-fix` | PB204, PB206, PB403 | Add `-mod=vendor` to `go build`; switch `npm install`→`ci` and `yarn install`→`--immutable`; drop setuid/setgid mode bits |

Safe fixes preserve behavior or restore a security default; unsafe fixes are
mechanical but change what the build does, so review them. An inline
`# pkglint: ignore=` on a finding's line also suppresses its fix. Findings whose
remediation isn't a mechanical rewrite (checksums, `.SRCINFO`) print a one-line
suggestion (`updpkgsums`, `makepkg --printsrcinfo`) instead.

## Rules

| Group | Rules | What they catch |
|-------|-------|-----------------|
| Integrity | PB101–PB110 | SKIP/weak checksums, unpinned VCS sources, unencrypted transports, source/url domain and forge-owner mismatches, DLAGENTS and other makepkg.conf overrides, checksum-count mismatches, missing install scripts |
| Hermeticity | PB201–PB206 | network access outside `prepare()`, `pip` without `--require-hashes`, unlocked `cargo`, implicit Go module downloads, disabled checksum databases |
| Execution | PB301–PB309 | top-level code, `eval`, decode-and-execute, download-and-execute (including `eval "$(curl ...)"` and `source <(wget ...)"` variants), `/dev/tcp`, unresolvable command names, embedded payloads, makepkg-internal function overrides, hidden bidi/zero-width characters |
| Filesystem | PB401–PB405 | writes outside `$srcdir`/`$pkgdir`, privilege escalation, setuid files, install steps that skip `$pkgdir`, writes to pacman/dynamic-linker/sudoers config |
| Scriptlets | PB501–PB502 | network access and persistence (crontabs, systemd units, shell profiles, login-capable users) in `.install` files running as root |
| Consistency | PB601–PB602 | PKGBUILD / .SRCINFO drift, network access in `pkgver()` |

`pkglint --rules` prints the full documentation for each.

Grading: any critical → **F**, any error → **D**, 3+ warns → **C**, 1–2 warns → **B**,
otherwise **A**.

A grade is a **static hygiene score, not a malware verdict** — it measures how reviewable
and reproducible a PKGBUILD is. A low grade means "worth reviewing", never "malicious",
and a high grade is not an endorsement. Static analysis cannot catch a malicious upstream
release pinned with a perfectly valid checksum.

## Report card site

`site/` generates a static "AUR Report Card" — grades, per-package finding pages,
a [rule reference](https://jamison.lahman.dev/pkglint/rules/) with a flagged/preferred
example for every check, `results.json`, and embeddable SVG badges. Findings whose rule
has an auto-fix are tagged with a `--fix`/`--unsafe-fix` badge so it's clear at a glance
what pkglint can rewrite for you:

```shell
go run ./site -maintainer Jamison -top 500 -out docs
```

It downloads the AUR metadata dump once a day, fetches package snapshots politely
(throttled, cached by `LastModified`), and scans everything in-process.

The generated site is checked into [`docs/`](docs/) and served at
<https://jamison.lahman.dev/pkglint/>. The [`Report card site`](.github/workflows/site.yml)
workflow regenerates it nightly and commits any changes.

## Roadmap

- A `makepkg` shim so AUR helpers lint before building (`yay --makepkg pkglint-makepkg`,
  paru `[bin] Makepkg`)
- Sandboxed builds: containerized `makepkg` with the package artifact installed on the
  host via `pacman -U`
- Hermetic builds: two-phase `makepkg -o` (network) / `makepkg -e` (`--network=none`),
  with these lint rules enforcing the conventions that make that split work

## License

GPLv3 — see [LICENSE](LICENSE).
