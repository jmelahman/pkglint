package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
)

// stateFor loads a PKGBUILD from a string and fingerprints it.
func stateFor(t *testing.T, content string, lastModified int64) sourceState {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg, err := pkgbuild.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return extractState(pkg, lastModified)
}

const driftBase = `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=("https://example.com/demo-1.0.0.tar.gz")
sha256sums=('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
`

func TestDriftNotes(t *testing.T) {
	t.Run("no previous state means no drift", func(t *testing.T) {
		cur := stateFor(t, driftBase, 200)
		if notes := driftNotes(sourceState{}, cur); notes != nil {
			t.Errorf("expected no drift on first sighting, got %v", notes)
		}
	})
	t.Run("same snapshot means no drift", func(t *testing.T) {
		prev := stateFor(t, driftBase, 100)
		cur := stateFor(t, driftBase, 100)
		if notes := driftNotes(prev, cur); notes != nil {
			t.Errorf("expected no drift for identical snapshot, got %v", notes)
		}
	})
	t.Run("checksum change under an unchanged URL is drift", func(t *testing.T) {
		prev := stateFor(t, driftBase, 100)
		tampered := strings.Replace(driftBase,
			"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", 1)
		cur := stateFor(t, tampered, 200)
		notes := driftNotes(prev, cur)
		if len(notes) != 1 || !strings.Contains(notes[0], "checksum for https://example.com/demo-1.0.0.tar.gz changed") {
			t.Errorf("expected checksum drift note, got %v", notes)
		}
	})
	t.Run("version bump with a new URL is not drift", func(t *testing.T) {
		prev := stateFor(t, driftBase, 100)
		bumped := strings.ReplaceAll(strings.Replace(driftBase,
			"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", 1),
			"1.0.0", "1.1.0")
		cur := stateFor(t, bumped, 200)
		if notes := driftNotes(prev, cur); notes != nil {
			t.Errorf("expected no drift for a version bump, got %v", notes)
		}
	})
	t.Run("commit pin moving without a pkgver change is drift", func(t *testing.T) {
		vcs := `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=("git+https://example.com/demo.git#commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
sha256sums=('SKIP')
`
		prev := stateFor(t, vcs, 100)
		moved := strings.Replace(vcs, "commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)
		cur := stateFor(t, moved, 200)
		notes := driftNotes(prev, cur)
		if len(notes) != 1 || !strings.Contains(notes[0], "pinned commit") {
			t.Errorf("expected commit drift note, got %v", notes)
		}
	})
	t.Run("commit pin moving with a pkgver bump is not drift", func(t *testing.T) {
		vcs := `pkgname=demo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=("git+https://example.com/demo.git#commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
sha256sums=('SKIP')
`
		prev := stateFor(t, vcs, 100)
		moved := strings.Replace(strings.Replace(vcs, "commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1), "pkgver=1.0.0", "pkgver=1.1.0", 1)
		cur := stateFor(t, moved, 200)
		if notes := driftNotes(prev, cur); notes != nil {
			t.Errorf("expected no drift for a pinned bump, got %v", notes)
		}
	})
}

func TestStateRoundTrip(t *testing.T) {
	cache := t.TempDir()
	st := map[string]sourceState{"demo": stateFor(t, driftBase, 123)}
	if err := saveState(cache, st); err != nil {
		t.Fatal(err)
	}
	got := loadState(cache)
	if got["demo"].LastModified != 123 || got["demo"].Pkgver != "1.0.0" {
		t.Errorf("state round trip lost data: %+v", got)
	}
	if len(got["demo"].Sums) != 1 {
		t.Errorf("expected one fingerprinted source, got %+v", got["demo"].Sums)
	}
}

func TestRenderDrift(t *testing.T) {
	results := []siteResult{{
		Name: "demo", Base: "demo", Version: "1.0-1", Grade: "A",
		Drift: []string{"sha256 checksum for https://example.com/demo.tar.gz changed (aaa → bbb) while the URL stayed the same"},
	}}
	out := t.TempDir()
	for _, sub := range []string{"rules", "package", "badge"} {
		if err := os.MkdirAll(filepath.Join(out, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := renderSite(out, results); err != nil {
		t.Fatalf("renderSite: %v", err)
	}
	pkg, err := os.ReadFile(filepath.Join(out, "package", "demo.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pkg), "Source drift since the previous scan") {
		t.Errorf("package page missing drift section:\n%s", pkg)
	}
	index, err := os.ReadFile(filepath.Join(out, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), "drifted") {
		t.Errorf("index missing drifted tile:\n%s", index)
	}
}
