package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSafeBase pins the filter that keeps untrusted AUR package bases from
// becoming path components in the published site.
func TestSafeBase(t *testing.T) {
	for _, tt := range []struct {
		name string
		want bool
	}{
		// Real-world shapes the AUR allows.
		{"python-foo", true},
		{"a.b+c@1", true},
		{"X", true},
		{"0ad", true},
		{"lib32-gcc-libs", true},
		// Hostile or otherwise unusable as a filename.
		{"../../evil", false},
		{"a/b", false},
		{"..", false},
		{".", false},
		{".hidden", false},
		{"", false},
		{"a..b", false},
		{"-leading-dash", false},
		{"back\\slash", false},
		{"space name", false},
		{"nul\x00byte", false},
		{"ctrl\x01char", false},
		{"new\nline", false},
		{"tilde~", false},
		{"semi;colon", false},
	} {
		if got := safeBase(tt.name); got != tt.want {
			t.Errorf("safeBase(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestSelectSeedDropsUnsafeBases proves the filter runs at the choke point, so
// no unsafe name reaches results, links, or output filenames.
func TestSelectSeedDropsUnsafeBases(t *testing.T) {
	who := "jmelahman"
	meta := []metaPackage{
		{PackageBase: "good-pkg", NumVotes: 10},
		{PackageBase: "../../evil", NumVotes: 9999},
		{PackageBase: "a/b", NumVotes: 9999},
		{PackageBase: "..", NumVotes: 9999},
		{PackageBase: "", NumVotes: 9999},
		// Unsafe names must be dropped even via the maintainer path, which
		// bypasses the top-N cutoff.
		{PackageBase: ".hidden", NumVotes: 1, Maintainer: &who},
		{PackageBase: "mine", NumVotes: 1, Maintainer: &who},
	}
	seed := selectSeed(meta, who, 100)
	got := map[string]bool{}
	for _, m := range seed {
		got[m.PackageBase] = true
		if !safeBase(m.PackageBase) {
			t.Errorf("selectSeed returned unsafe base %q", m.PackageBase)
		}
	}
	if len(seed) != 2 || !got["good-pkg"] || !got["mine"] {
		t.Errorf("selectSeed = %v, want exactly [good-pkg mine]", got)
	}
}

// TestSelectSeedIsDeterministic pins the tie-break at the top-N cutoff. The
// bases come out of a map and sort.Slice is not stable, so without one the
// cutoff falls differently on every run and packages appear on the site, 404,
// and come back over input that never changed.
func TestSelectSeedIsDeterministic(t *testing.T) {
	// Every base carries the same vote count, so the cutoff is decided purely
	// by the tie-break, and the input order is not the answer.
	var meta []metaPackage
	for _, n := range []string{"delta", "alpha", "echo", "charlie", "bravo"} {
		meta = append(meta, metaPackage{PackageBase: n, NumVotes: 42})
	}
	want := []string{"alpha", "bravo", "charlie"}
	for i := 0; i < 32; i++ {
		var got []string
		for _, m := range selectSeed(meta, "", 3) {
			got = append(got, m.PackageBase)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: selectSeed = %v, want %v", i, got, want)
		}
	}
}

// TestDownloadRefusesOversizedBody feeds download a body past the ceiling from
// a loopback test server and asserts it errors and leaves nothing behind.
func TestDownloadRefusesOversizedBody(t *testing.T) {
	defer restoreDownloadCeiling(t, 1<<10)()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), 8<<10))
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "sub", "big.bin")
	err := download(srv.URL, path)
	if err == nil {
		t.Fatal("download of an oversized body returned nil error")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %v, want a size-ceiling error", err)
	}
	for _, p := range []string{path, path + ".tmp"} {
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Errorf("%s should not exist after a refused download (stat: %v)", p, statErr)
		}
	}
}

// TestDownloadWithinCeiling guards the happy path: bounding the copy must not
// truncate or otherwise corrupt a legitimate body.
func TestDownloadWithinCeiling(t *testing.T) {
	defer restoreDownloadCeiling(t, 1<<10)()

	body := bytes.Repeat([]byte("y"), 1<<10) // exactly at the ceiling
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "ok.bin")
	if err := download(srv.URL, path); err != nil {
		t.Fatalf("download: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("downloaded %d bytes, want %d", len(got), len(body))
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind (stat: %v)", err)
	}
}

func restoreDownloadCeiling(t *testing.T, limit int64) func() {
	t.Helper()
	prev := maxDownloadBytes
	maxDownloadBytes = limit
	return func() { maxDownloadBytes = prev }
}

// TestDecodeMetaBounded shows the metadata decoder stops at the ceiling
// instead of inflating an arbitrarily large gzip stream into memory.
func TestDecodeMetaBounded(t *testing.T) {
	// A highly compressible payload: ~1 MiB of JSON from a few KiB of gzip.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`[{"PackageBase":"a","Description":"`))
	zw.Write(bytes.Repeat([]byte("A"), 1<<20))
	zw.Write([]byte(`"}]`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	bomb := buf.Bytes()

	prev := maxMetaDecompressed
	defer func() { maxMetaDecompressed = prev }()

	maxMetaDecompressed = 4 << 10
	zr, err := gzip.NewReader(bytes.NewReader(bomb))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeMeta(zr); err == nil {
		t.Error("decodeMeta accepted a stream past the ceiling, want a decode error")
	}

	// With headroom the same stream decodes fine, so the bound is what
	// rejected it above and legitimate dumps are unaffected.
	maxMetaDecompressed = 1 << 30
	zr, err = gzip.NewReader(bytes.NewReader(bomb))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := decodeMeta(zr)
	if err != nil {
		t.Fatalf("decodeMeta under an ample ceiling: %v", err)
	}
	if len(meta) != 1 || meta[0].PackageBase != "a" {
		t.Errorf("decodeMeta = %+v, want one package base %q", meta, "a")
	}
}
