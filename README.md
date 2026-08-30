# pkglint

A security-focused linter for Arch Linux packages.

pkglint statically analyzes PKGBUILDs and their install scriptlets — **without ever
sourcing them** — and reports findings about source integrity, build hermeticity, code
execution, and persistence patterns, condensed into a letter grade per package. It also
reproduces makepkg's own build-breaking metadata checks, so a PKGBUILD that would fail to
build is caught (and, where the fix is mechanical, rewritten) before you run makepkg. It is
built on a real bash AST ([mvdan.cc/sh](https://github.com/mvdan/sh)), so the
quoting/line-continuation tricks that evade regex-based scanners don't work here.

Built packages (`*.pkg.tar.zst` and friends) are first-class inputs too: pkglint inspects
the archive the way namcap does — ELF hardening (PIE, RELRO, executable stacks, text
relocations, RPATH), stripping and placement, dependencies inferred from linked shared
libraries and script shebangs (via pacman's local database), packaged `.INSTALL`
scriptlets, and filesystem hygiene from FHS layout to stale python bytecode — while
**never executing anything from the package** (no `ldd`, no interpreter launches; ELF
files are parsed, not loaded).

```
$ pkglint ~/pkgbuilds/somepkg
somepkg: grade F, 3 finding(s)
  PKGBUILD:16:3: critical [PB304] a network download is piped straight into bash and executed
  PKGBUILD:11:1: error [PB101] remote source "http://..." has no checksum (SKIP): the download is never verified
  PKGBUILD:24:3: error [PB402] sudo escalates privileges during a build; ...

1 package linted: 1 with findings
```

Packages with nothing to report stay out of the way — they are only counted in
the closing summary line (`--verbose` lists them individually).

## Install

**AUR**

```
yay -S pkglint
```

**PyPi**

```
uv tool install pkglint
```

**Go**

```shell
go install github.com/jmelahman/pkglint@latest
```

## Usage

```shell
pkglint [flags] [path ...]     # paths are package dirs, PKGBUILD files,
                               # or built packages (*.pkg.tar.*) (default: .)

  --format text|json|sarif     # output format (sarif = SARIF 2.1.0, for code scanning)
  --fail-on SEVERITY           # exit 1 at or above: info, warn, error (default), critical, never
  --ignore PB105,PB206         # disable rules
  --color auto|always|never    # colorize text output (auto = only on a terminal; honors NO_COLOR)
  --verbose                    # list packages with no findings individually, not just in the summary
  --rules                      # list every rule with its documentation
  --fix                        # apply safe auto-fixes in place
  --unsafe-fix                 # also apply behavior-changing fixes (implies --fix)
  --diff                       # with --fix/--unsafe-fix/--add-ignores: show changes instead of writing
  --offline                    # with --fix: skip fixes needing network (e.g. VCS ref resolution)
  --add-ignores                # insert ignore directives suppressing every current finding
  --no-inline-ignores          # disregard ignore directives (audit an untrusted package)
```

Suppress a reviewed, intentional finding inline:

```bash
# pkglint: ignore=PB204
go build -o "$pkgname" .
```

The directive covers its own line and the line below it, in the file it appears
in only: an `ignore=` in an `.install` scriptlet never affects the `PKGBUILD`,
or vice versa. `--add-ignores` writes these directives for you, one per finding
still reported, so a package can adopt pkglint without first fixing (or while
deliberately keeping) what it flags; `--diff` previews the insertions.

Directives are audited, not just obeyed. A directive that no longer matches a
finding on its line or the next — the issue was fixed, or the ID was never a
pkglint rule — is itself flagged (PB913, `stale-ignore-directive`), and `--fix`
deletes it, so a fixed issue cannot leave behind a comment that would silence
its return. And when reviewing a package you don't trust, `--no-inline-ignores`
disregards every directive and reports whatever the maintainer suppressed.

### Auto-fixing

`--fix` rewrites what it can and prints every change; `--diff` previews without
writing. Fixes come in two tiers:

| Tier   | Flag           | Rules                             | What it does                                                                                                                                                                                                                                                               |
| ------ | -------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Safe   | `--fix`        | PB103, PB205, PB705, PB708, PB913, PB916 | Pin a mutable VCS tag/branch to its current commit (via `git ls-remote`); delete Go verification-disabling env settings; strip a leading slash from `backup` entries; wrap a scalar list field (`depends=foo`) in an array (`depends=(foo)`); remove stale ignore directives; insert `-modcacherw` into go commands so the module cache stays removable |
| Unsafe | `--unsafe-fix` | PB203, PB204, PB206–PB209, PB403, PB914–PB915 | Append `--locked` to `cargo` (fails the build if no Cargo.lock ships); add a `go mod download` prepare() step; insert `-buildmode=pie` and `-trimpath` into `go build`; switch `npm install`→`ci` and `yarn install`→`--immutable`; append `--frozen-lockfile` to `pnpm`/`bun install`, `--no-scripts` to `composer install`, `--frozen` to `bundle install` and `uv sync`; drop setuid/setgid mode bits |

Safe fixes preserve behavior or restore a security default; unsafe fixes are
mechanical but change what the build does, so review them. An inline
`# pkglint: ignore=` on a finding's line also suppresses its fix. Findings whose
remediation isn't a mechanical rewrite (checksums, `.SRCINFO`) print a one-line
suggestion (`updpkgsums`, `makepkg --printsrcinfo`) instead.

### Commit hook

This repo ships hooks for any runner that understands the
`.pre-commit-config.yaml` convention, so a packaging tree can lint its
PKGBUILDs on every commit:

```yaml
repos:
  - repo: https://github.com/jmelahman/pkglint
    rev: v1.2.0
    hooks:
      - id: pkglint
```

Three hook ids are available: `pkglint` builds from source with the Go
toolchain, `pkglint-system` runs whatever `pkglint` is already on `$PATH`, and
`pkglint-fix` applies the safe auto-fixes in place (offline by default). Tune
any of them with e.g. `args: [--ignore, PB105, --fail-on, critical]`.

## Rules

| Group         | Rules       | What they catch                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Integrity     | PB101–PB114 | SKIP/weak/malformed checksums, unpinned VCS sources, unencrypted transports, source/url domain and forge-owner mismatches, DLAGENTS and other makepkg.conf overrides, checksum-count mismatches, missing install scripts, PGP signatures without pinned keys, insecure signature transport, unused validpgpkeys                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Hermeticity   | PB201–PB209 | network access outside `prepare()`, `pip`/`uv pip` without `--require-hashes`, unlocked `cargo`/npm/yarn/pnpm/bun/composer/bundler/uv/poetry installs, implicit Go module downloads and mutable `@latest` refs, disabled checksum databases                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Execution     | PB301–PB309 | top-level code, `eval`, decode-and-execute, download-and-execute (including `eval "$(curl ...)"` and `source <(wget ...)"` variants), `/dev/tcp`, unresolvable command names, embedded payloads, makepkg-internal function overrides, hidden bidi/zero-width characters                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Filesystem    | PB401–PB405 | writes outside `$srcdir`/`$pkgdir`, privilege escalation, setuid files and setcap capability grants, install steps that skip `$pkgdir`, writes to pacman/dynamic-linker/sudoers config                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Scriptlets    | PB501–PB504 | network access and persistence (crontabs, systemd units, shell profiles, login-capable users) in `.install` files running as root, unparseable scriptlets, commands pacman hooks already run                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Consistency   | PB601–PB603 | PKGBUILD / .SRCINFO drift, network access in `pkgver()`, provides/replaces/conflicts claims on core system packages                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Correctness   | PB701–PB711 | makepkg build-breakers: invalid pkgname/pkgver/pkgrel/epoch, backup leading slash, unknown `options`, `provides` comparison operators, scalar-vs-array field types, schema variables set inside `package()`, missing/duplicate/mixed `arch`, VCS sources without their client in makedepends                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Built package | PB801–PB839 | everything namcap checks in a `.pkg.tar.*`: ELF in `any` packages and nonstandard paths, executable stacks, text relocations, missing RELRO, non-PIE executables, unstripped binaries, insecure RPATH/RUNPATH, missing/unused library and interpreter dependencies (resolved through pacman's database, statically — no `ldd`), stale soname declarations, pkg-config requirements, FHS layout, permissions and ownership, empty directories, invalid filenames, cross-directory hardlinks, dangling symlinks, `.la`/`perllocal.pod`/info `dir`/MIME-cache landmines, stale python bytecode, `site-packages/tests`, systemd/D-Bus units under `/etc`, missing license and backup files, doc-heavy packages, sphinx caches — plus the full scriptlet analysis over the packaged `.INSTALL` |
| Style         | PB901–PB917 | namcap's PKGBUILD conventions: hardcoded architectures instead of `$CARCH`, custom variables without `_` prefix, `$startdir`, redundant makedepends, pinned SourceForge mirrors, pkgname repeated in pkgdesc, makepkg-internal output helpers, missing Maintainer tag, uppercase package names, missing pkgdesc/url/license, version-only download names, depends duplicated in optdepends, stale ignore directives; plus the [Arch Go packaging guidelines](https://wiki.archlinux.org/title/Go_package_guidelines): `go build` without `-buildmode=pie` or `-trimpath`, module caches written read-only (no `-modcacherw`), CFLAGS/LDFLAGS never forwarded to cgo                                                                                                                                                                                                                                                                                                                                                                                                |

`pkglint --rules` prints the full documentation for each.
A full reference including examples of each rule is available in the [documentation](https://jamison.lahman.dev/pkglint/rules/).

### Relationship to namcap

pkglint covers namcap's rule set — both the PKGBUILD checks and the built-package
checks — with a few deliberate differences: nothing from the analyzed package is ever
executed (namcap runs `ldd -r -u` on packaged binaries; pkglint compares dynamic symbol
tables instead), findings the lint host cannot actually verify (a library owned by a
package that isn't installed here, a declared dependency that isn't installed) are
reported informationally instead of as hard errors, and everything is folded into the
same graded, suppressible, JSON/SARIF-capable reporting the PKGBUILD rules use.
Dependency inference reads pacman's local database directly (`/var/lib/pacman/local`)
and degrades gracefully on non-Arch hosts by skipping just those rules.

Grading: any critical → **F**, any error → **D**, 3+ warns → **C**, 1–2 warns → **B**,
otherwise **A**.

A grade is a **static hygiene score, not a malware verdict** — it measures how reviewable
and reproducible a PKGBUILD is. A low grade means "worth reviewing", never "malicious",
and a high grade is not an endorsement. Static analysis cannot catch a malicious upstream
release pinned with a perfectly valid checksum.

## License

GPLv3 — see [LICENSE](LICENSE).
