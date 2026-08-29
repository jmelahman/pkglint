package pkgbuild

import (
	"strings"
	"testing"
)

// TestRescueArrayWordContinuations covers the upstream lexer gap where `=` and
// `#` directly after an expansion inside array parens end the word: bash keeps
// both as plain word characters. Every case here passes `bash -n`.
func TestRescueArrayWordContinuations(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		v    string
		want []string
	}{
		{
			name: "provides with unquoted version",
			src:  "_pkgname=ag\npkgver=2.2\nprovides=($_pkgname=$pkgver)\n",
			v:    "provides",
			want: []string{"$_pkgname=$pkgver"},
		},
		{
			name: "braced expansions",
			src:  "provides=(${_pkgname}=${pkgver})\n",
			v:    "provides",
			// RenderWord renders ${x} as $x; the `=` between the two
			// expansions is what the rescue restores.
			want: []string{"$_pkgname=$pkgver"},
		},
		{
			name: "append form across lines",
			src:  "depends=(glibc)\ndepends+=(\n  $_name=$pkgver\n)\n",
			v:    "depends",
			want: []string{"glibc", "$_name=$pkgver"},
		},
		{
			name: "vcs fragment after expansion",
			src:  "source=($pkgname::git+https://example.com/$pkgname#tag=$pkgver)\n",
			v:    "source",
			want: []string{"$pkgname::git+https://example.com/$pkgname#tag=$pkgver"},
		},
		{
			name: "fragment after quoted part",
			src:  "source=(\"$pkgname-$pkgver\"::git+$url#tag=$pkgver)\n",
			v:    "source",
			want: []string{"$pkgname-$pkgver::git+$url#tag=$pkgver"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := loadPKGBUILD(t, tc.src)
			got := pkg.Vars[tc.v]
			if got == nil {
				t.Fatalf("variable %q not extracted", tc.v)
			}
			if len(got.Values) != len(tc.want) {
				t.Fatalf("values = %q, want %q", got.Values, tc.want)
			}
			for i, w := range tc.want {
				if got.Values[i] != w {
					t.Errorf("values[%d] = %q, want %q", i, got.Values[i], w)
				}
			}
			// The unit must keep the original bytes: findings and --fix edits
			// slice Raw by AST offsets.
			if string(pkg.PKGBUILD.Raw) != tc.src {
				t.Errorf("Raw was modified:\n%q", pkg.PKGBUILD.Raw)
			}
		})
	}
}

// TestRescueAssocSubscript covers string keys in associative-array subscripts,
// which upstream force-parses as arithmetic.
func TestRescueAssocSubscript(t *testing.T) {
	src := "declare -g -A _sums\n" +
		"_sums[7.1]=1b231f3988603dbec4e857e247784295\n" +
		"_sums[7.2]=d9edd2bb89870dc61692e73f81fe0efa\n" +
		"pkgver=7.1.3\n"
	pkg := loadPKGBUILD(t, src)
	if string(pkg.PKGBUILD.Raw) != src {
		t.Errorf("Raw was modified")
	}
	if v, ok := pkg.Scalar("pkgver"); !ok || v != "7.1.3" {
		t.Errorf("pkgver = %q, %v; want 7.1.3", v, ok)
	}
	// The restored subscript text must survive in the source: printing the
	// statement's span from Raw is how findings quote code.
	if !strings.Contains(string(pkg.PKGBUILD.Raw), "_sums[7.1]=") {
		t.Errorf("subscript text lost from Raw")
	}
}

// TestRescueSubscriptBeforeParamOp covers a string subscript inside a
// parameter expansion that continues with an operator rather than `}`:
// `${_supported[armv8.1-a]:-}`. Passes `bash -n`.
func TestRescueSubscriptBeforeParamOp(t *testing.T) {
	src := "check() {\n  declare -A _supported\n  if [[ -n \"${_supported[armv8.1-a]:-}\" ]]; then\n    :\n  fi\n}\n"
	pkg := loadPKGBUILD(t, src)
	if string(pkg.PKGBUILD.Raw) != src {
		t.Errorf("Raw was modified:\n%q", pkg.PKGBUILD.Raw)
	}
	if pkg.PKGBUILD.Functions["check"] == nil {
		t.Errorf("check() not extracted")
	}
	if !strings.Contains(string(pkg.PKGBUILD.Raw), "[armv8.1-a]:-") {
		t.Errorf("subscript text lost from Raw")
	}
}

// TestRescueInlineArray covers `arr+=( x ) cmd`, which bash accepts as an
// assignment in the command's temporary environment.
func TestRescueInlineArray(t *testing.T) {
	src := "build() {\n  local _conf=()\n  _conf+=( '--without-gsettings' ) :\n}\n"
	pkg := loadPKGBUILD(t, src)
	if string(pkg.PKGBUILD.Raw) != src {
		t.Errorf("Raw was modified")
	}
	if pkg.PKGBUILD.Functions["build"] == nil {
		t.Errorf("build() not extracted")
	}
}

// TestRescueArithFallback covers `$((( cmd )) ...)`: bash retries the failed
// arithmetic parse as a command substitution; upstream reports the unmatched
// `))`. Both cases pass `bash -n`.
func TestRescueArithFallback(t *testing.T) {
	t.Run("configure flag toggle", func(t *testing.T) {
		src := "flag=1\nbuild() {\n  ./configure $((( flag )) && echo --enable-tests)\n}\n"
		pkg := loadPKGBUILD(t, src)
		if string(pkg.PKGBUILD.Raw) != src {
			t.Errorf("Raw was modified:\n%q", pkg.PKGBUILD.Raw)
		}
		if pkg.PKGBUILD.Functions["build"] == nil {
			t.Errorf("build() not extracted")
		}
		// The restored paren text must survive: findings quote code from Raw.
		if !strings.Contains(string(pkg.PKGBUILD.Raw), "$((( flag ))") {
			t.Errorf("arithmetic command text lost from Raw")
		}
	})

	t.Run("assignment form", func(t *testing.T) {
		src := "a=$((( x )) && echo y)\n"
		pkg := loadPKGBUILD(t, src)
		if string(pkg.PKGBUILD.Raw) != src {
			t.Errorf("Raw was modified:\n%q", pkg.PKGBUILD.Raw)
		}
	})

	// Real arithmetic in the same spelling must not round-trip through the
	// rescue: `$(((1+2)*3))` parses as arithmetic on the first attempt.
	t.Run("healthy arithmetic untouched", func(t *testing.T) {
		pkg := loadPKGBUILD(t, "a=$(((1+2)*3))\n")
		if pkg.Vars["a"] == nil {
			t.Fatal("a not extracted")
		}
	})
}

// TestRescueHeredocText covers non-shell text — Markdown code fences, inline
// backquotes — in an unquoted heredoc body. Bash defers the body's expansions
// to when the redirection runs, so `bash -n` accepts this; upstream parses the
// backquote substitution eagerly and fails on its content.
func TestRescueHeredocText(t *testing.T) {
	src := "package() {\n  cat <<EOF\nNotes:\n```\nfoo(s) bar\n```\nUses `file`, see $pkgdir docs.\nEOF\n}\n"
	pkg := loadPKGBUILD(t, src)
	if string(pkg.PKGBUILD.Raw) != src {
		t.Errorf("Raw was modified:\n%q", pkg.PKGBUILD.Raw)
	}
	if pkg.PKGBUILD.Functions["package"] == nil {
		t.Errorf("package() not extracted")
	}
	if !strings.Contains(string(pkg.PKGBUILD.Raw), "Uses `file`") {
		t.Errorf("backquote text lost from Raw")
	}
}

// TestRescueGivesUp pins the failure mode: input that bash itself rejects, or
// that the rescue cannot restore faithfully, must surface the original parse
// error rather than a silently divergent AST.
func TestRescueGivesUp(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		// bash also rejects this: the comment swallows the closing paren.
		{"comment at element start", "a=(#c)\n"},
		// Unterminated array; nothing to rescue.
		{"unterminated array", "provides=($x=$y\n"},
		// The rewritten `~` would become an arithmetic operator, not a
		// literal, so restoration must veto the rescue.
		{"expansion glued to arith base", "a=$(($x#2))\n"},
		// bash rejects this too: the paren error is outside any heredoc, so
		// no rescue may apply.
		{"paren in ordinary command", "build() {\n  echo task(s)\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseUnit("PKGBUILD", []byte(tc.src), false); err == nil {
				t.Fatalf("parseUnit accepted %q; want the original parse error", tc.src)
			}
		})
	}
}

// TestRescueLeavesHealthyInputAlone: a byte-identical AST question — sources
// with these characters in ordinary positions must not round-trip through the
// rescue at all (strict parse already accepts them).
func TestRescueLeavesHealthyInputAlone(t *testing.T) {
	src := "pkgver=1 # release=$pkgver\nopts=(-Db_lto=true \"x=$pkgver\" 'lit=#')\n"
	pkg := loadPKGBUILD(t, src)
	v := pkg.Vars["opts"]
	if v == nil {
		t.Fatal("opts not extracted")
	}
	want := []string{"-Db_lto=true", "x=$pkgver", "lit=#"}
	for i, w := range want {
		if v.Values[i] != w {
			t.Errorf("values[%d] = %q, want %q", i, v.Values[i], w)
		}
	}
}
