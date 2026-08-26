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
}
