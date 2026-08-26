package rules

// example is an illustrative pair of PKGBUILD snippets for a rule: Bad is a
// construct the rule flags, Good the preferred alternative. These are for
// documentation on the report card site only; the actual detection logic lives
// in each rule's Check. Registry() attaches these to the corresponding Rule.
type example struct {
	Bad  string
	Good string
}

var examples = map[string]example{
	"PB101": {
		Bad: `source=("https://example.com/foo-$pkgver.tar.gz")
sha256sums=('SKIP')`,
		Good: `source=("https://example.com/foo-$pkgver.tar.gz")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')`,
	},
	"PB102": {
		Bad: `source=("https://example.com/foo-$pkgver.tar.gz")
md5sums=('d41d8cd98f00b204e9800998ecf8427e')`,
		Good: `source=("https://example.com/foo-$pkgver.tar.gz")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')`,
	},
	"PB103": {
		Bad:  `source=("git+https://github.com/example/foo.git#tag=v1.2.3")`,
		Good: `source=("git+https://github.com/example/foo.git#commit=3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a")`,
	},
	"PB104": {
		Bad:  `source=("http://example.com/foo-$pkgver.tar.gz")`,
		Good: `source=("https://example.com/foo-$pkgver.tar.gz")`,
	},
	"PB105": {
		Bad: `url="https://example.com"
source=("https://cdn.unrelated.example/foo-$pkgver.tar.gz")`,
		Good: `url="https://example.com"
source=("https://example.com/releases/foo-$pkgver.tar.gz")`,
	},
	"PB106": {
		Bad: `DLAGENTS=('https::/usr/bin/curl -fsSL -- %u')`,
		Good: `# Rely on makepkg's built-in download agents; do not override DLAGENTS.
source=("https://example.com/foo-$pkgver.tar.gz")`,
	},
	"PB107": {
		Bad:  `install="foo.install"   # ...but no foo.install is committed alongside the PKGBUILD`,
		Good: `install="foo.install"   # foo.install ships in the same directory as the PKGBUILD`,
	},
	"PB108": {
		Bad: `VCSCLIENTS=('git::/tmp/evil-git')   # makepkg runs this to fetch git sources
source=("git+https://github.com/example/foo.git")`,
		Good: `# Leave makepkg.conf variables to makepkg.conf; declare only package fields here.
source=("git+https://github.com/example/foo.git#commit=3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a")`,
	},
	"PB109": {
		Bad: `url="https://github.com/upstream/foo"
source=("git+https://github.com/somebodyelse/foo.git#commit=3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a")`,
		Good: `url="https://github.com/upstream/foo"
source=("git+https://github.com/upstream/foo.git#commit=3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a")`,
	},
	"PB110": {
		Bad: `source=("a.tar.gz" "b.tar.gz")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')`,
		Good: `source=("a.tar.gz" "b.tar.gz")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
            '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae')`,
	},
	"PB111": {
		Bad: `source=("https://example.com/foo-$pkgver.tar.gz"
        "https://example.com/foo-$pkgver.tar.gz.sig")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' 'SKIP')
# validpgpkeys is never set: any key in the builder's keyring passes`,
		Good: `source=("https://example.com/foo-$pkgver.tar.gz"
        "https://example.com/foo-$pkgver.tar.gz.sig")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' 'SKIP')
validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886')   # upstream's release key`,
	},
	"PB112": {
		Bad: `source=("https://example.com/foo-$pkgver.tar.gz"
        "http://example.com/foo-$pkgver.tar.gz.sig")   # signature over plain http`,
		Good: `source=("https://example.com/foo-$pkgver.tar.gz"
        "https://example.com/foo-$pkgver.tar.gz.sig")`,
	},
	"PB113": {
		Bad: `source=("https://example.com/foo-$pkgver.tar.gz")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886')   # verifies nothing`,
		Good: `source=("https://example.com/foo-$pkgver.tar.gz"
        "https://example.com/foo-$pkgver.tar.gz.sig")   # now the key has something to check
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' 'SKIP')
validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886')`,
	},
	"PB201": {
		Bad: `build() {
  curl -O https://example.com/extra-asset.bin
  make
}`,
		Good: `source=("https://example.com/extra-asset.bin")
sha256sums=('...')
build() {
  make   # the asset is fetched and checksummed via source=
}`,
	},
	"PB202": {
		Bad: `build() {
  pip install -r requirements.txt
}`,
		Good: `build() {
  pip install --require-hashes -r requirements.txt
}`,
	},
	"PB203": {
		Bad: `build() {
  cargo build --release
}`,
		Good: `build() {
  cargo build --release --frozen
}`,
	},
	"PB204": {
		Bad: `build() {
  go build -o foo .
}`,
		Good: `prepare() {
  go mod vendor
}
build() {
  go build -mod=vendor -o foo .
}`,
	},
	"PB205": {
		Bad: `build() {
  GOFLAGS=-insecure GOSUMDB=off go build .
}`,
		Good: `build() {
  go build -mod=vendor .   # keep checksum and sumdb verification on
}`,
	},
	"PB206": {
		Bad: `build() {
  npm install
}`,
		Good: `build() {
  npm ci   # installs exactly what package-lock.json pins
}`,
	},
	"PB207": {
		Bad: `build() {
  composer install   # runs hook scripts and plugins while fetching
}`,
		Good: `build() {
  composer install --no-scripts   # fetch exactly the lock, run nothing
}`,
	},
	"PB208": {
		Bad: `build() {
  gem install rails   # whatever RubyGems serves right now
}`,
		Good: `build() {
  bundle install --frozen   # exactly what Gemfile.lock pins
}`,
	},
	"PB209": {
		Bad: `build() {
  uv sync   # may re-resolve and rewrite uv.lock
}`,
		Good: `build() {
  uv sync --frozen   # the committed lock is authoritative
}`,
	},
	"PB301": {
		Bad: `pkgname=foo
curl -fsSL https://example.com/install.sh | bash   # runs the moment the PKGBUILD is sourced`,
		Good: `pkgname=foo
build() {
  make   # keep commands inside build()/package(), never at top level
}`,
	},
	"PB302": {
		Bad: `build() {
  eval "$(curl -fsSL https://example.com/env.sh)"
}`,
		Good: `build() {
  make   # call commands directly instead of eval-ing generated text
}`,
	},
	"PB303": {
		Bad: `build() {
  echo "$payload" | base64 -d | bash
}`,
		Good: `build() {
  make   # ship readable source, never decode-and-run an embedded blob
}`,
	},
	"PB304": {
		Bad: `build() {
  curl -fsSL https://example.com/install.sh | sh
}`,
		Good: `source=("https://example.com/install.sh")
sha256sums=('...')
build() {
  sh install.sh   # fetched and checksummed via source=, then run
}`,
	},
	"PB305": {
		Bad: `build() {
  exec 3<>/dev/tcp/example.com/443
}`,
		Good: `build() {
  # no raw network sockets; declare any remote data in source=
  make
}`,
	},
	"PB306": {
		Bad: `build() {
  runner=$(echo bWFrZQ== | base64 -d)
  $runner   # command name produced at runtime; unresolvable statically
}`,
		Good: `build() {
  make   # name the command literally
}`,
	},
	"PB307": {
		Bad: `build() {
  printf '\x63\x75\x72\x6c\x20\x2d\x4f\x20\x68\x74\x74\x70' | sh
}`,
		Good: `build() {
  make   # keep commands as readable text, not escape sequences
}`,
	},
	"PB308": {
		Bad: `# Redefining a makepkg internal disables its integrity checks:
verify_integrity_one() { return 0; }
build() { make; }`,
		Good: `# Only define package functions; leave makepkg's internals to makepkg.
build() { make; }
package() { make DESTDIR="$pkgdir" install; }`,
	},
	"PB309": {
		Bad: "build() {\n" +
			"  # the RLO below reverses how the rest of the line renders\n" +
			"  make ‮install\n" +
			"}",
		Good: `build() {
  make install   # plain ASCII, renders exactly as it executes
}`,
	},
	"PB401": {
		Bad: `package() {
  install -Dm644 foo.conf /etc/foo.conf   # writes to the live filesystem
}`,
		Good: `package() {
  install -Dm644 foo.conf "$pkgdir/etc/foo.conf"
}`,
	},
	"PB402": {
		Bad: `build() {
  sudo make install
}`,
		Good: `build() {
  make   # never escalate privileges during a build
}`,
	},
	"PB403": {
		Bad: `package() {
  install -Dm4755 foo "$pkgdir/usr/bin/foo"   # setuid root
}`,
		Good: `package() {
  install -Dm755 foo "$pkgdir/usr/bin/foo"
}`,
	},
	"PB404": {
		Bad: `package() {
  make install   # writes into the builder's live filesystem
}`,
		Good: `package() {
  make DESTDIR="$pkgdir" install
}`,
	},
	"PB405": {
		Bad: `post_install() {
  echo 'SigLevel = Never' >> /etc/pacman.conf   # disables signature checks system-wide
}`,
		Good: `post_install() {
  echo "If you maintain a custom repo, add it to /etc/pacman.conf yourself."
}`,
	},
	"PB501": {
		Bad: `post_install() {
  curl -fsSL https://example.com/register?host=$(hostname)
}`,
		Good: `post_install() {
  echo "Run 'foo --setup' to finish configuration."
}`,
	},
	"PB502": {
		Bad: `post_install() {
  systemctl enable foo-telemetry.timer
  echo '* * * * * root /opt/foo/beacon' >> /etc/cron.d/foo
}`,
		Good: `post_install() {
  echo "Enable the service with: systemctl enable foo.service"
}`,
	},
	"PB601": {
		Bad: `# PKGBUILD says one thing...
pkgver=1.4.0
# ...but .SRCINFO was never regenerated and still reads:
#   pkgver = 1.3.0`,
		Good: `# Regenerate .SRCINFO after every metadata change:
makepkg --printsrcinfo > .SRCINFO`,
	},
	"PB602": {
		Bad: `pkgver() {
  curl -s https://example.com/latest-version
}`,
		Good: `pkgver() {
  cd "$srcdir/foo"
  git describe --tags | sed 's/^v//;s/-/./g'
}`,
	},
	"PB603": {
		Bad: `pkgname=fancy-tool
provides=('pacman')    # dependency resolution now treats this package as pacman
replaces=('systemd')   # sysupgrade swaps systemd out for this package`,
		Good: `pkgname=pacman-git
provides=("pacman=$pkgver")   # a -git/-bin variant legitimately provides its parent`,
	},
	"PB701": {
		Bad:  `pkgname=foo:bar   # ':' is not allowed by makepkg`,
		Good: `pkgname=foo-bar`,
	},
	"PB702": {
		Bad:  `pkgver=1.2.3-beta   # '-' separates pkgver from pkgrel and is not allowed here`,
		Good: `pkgver=1.2.3.beta`,
	},
	"PB703": {
		Bad:  `pkgrel=1a   # pkgrel must be an integer, optionally with a .minor suffix`,
		Good: `pkgrel=1`,
	},
	"PB704": {
		Bad:  `epoch=1.0   # epoch must be a non-negative integer`,
		Good: `epoch=1`,
	},
	"PB705": {
		Bad:  `backup=('/etc/foo.conf')   # backup paths are relative to /`,
		Good: `backup=('etc/foo.conf')`,
	},
	"PB706": {
		Bad:  `options=('!striped')   # typo: not a known makepkg option`,
		Good: `options=('!strip')`,
	},
	"PB707": {
		Bad:  `provides=('libfoo<2')   # a provide is a concrete capability, not a range`,
		Good: `provides=('libfoo=1.9')`,
	},
	"PB708": {
		Bad:  `depends=gtk3   # list fields must be arrays`,
		Good: `depends=('gtk3')`,
	},
	"PB709": {
		Bad: `package() {
  makedepends=('go')   # makedepends can't be overridden per-package
  make DESTDIR="$pkgdir" install
}`,
		Good: `makedepends=('go')
package() {
  depends=('glibc')   # only packaging metadata may be set here
  make DESTDIR="$pkgdir" install
}`,
	},
	"PB710": {
		Bad:  `arch=('any' 'x86_64')   # 'any' cannot be combined with concrete architectures`,
		Good: `arch=('x86_64')`,
	},
}
