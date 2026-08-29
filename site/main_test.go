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
	"time"

	"github.com/jmelahman/pkglint/internal/rules"
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
	seed := selectSeed(meta, who, 100, 0, time.Now())
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

// TestSelectSeedIncludesCoMaintained pins the -maintainer flag's reach: the
// flag exists so somebody can keep every package they answer for on the site,
// and co-maintainership is answering for a package under another title.
func TestSelectSeedIncludesCoMaintained(t *testing.T) {
	who, other := "jmelahman", "somebody-else"
	meta := []metaPackage{
		{PackageBase: "theirs", NumVotes: 50, Maintainer: &other},
		{PackageBase: "shared", NumVotes: 1, Maintainer: &other, CoMaintainers: []string{"helper", who}},
		{PackageBase: "mine", NumVotes: 1, Maintainer: &who},
	}
	got := map[string]bool{}
	for _, m := range selectSeed(meta, who, 0, 0, time.Now()) {
		got[m.PackageBase] = true
	}
	if len(got) != 2 || !got["mine"] || !got["shared"] {
		t.Errorf("selectSeed = %v, want exactly [mine shared]", got)
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
		for _, m := range selectSeed(meta, "", 3, 0, time.Now()) {
			got = append(got, m.PackageBase)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: selectSeed = %v, want %v", i, got, want)
		}
	}
}

// TestSelectSeedWindow pins the recency window: the corpus is what the AUR has
// seen an update to lately, and -top is what keeps a heavily-installed but
// long-stable package on the site anyway.
func TestSelectSeedWindow(t *testing.T) {
	now := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	ago := func(days int) int64 { return now.AddDate(0, 0, -days).Unix() }
	meta := []metaPackage{
		{PackageBase: "fresh", NumVotes: 1, LastModified: ago(30)},
		{PackageBase: "edge", NumVotes: 2, LastModified: ago(365) + 60},
		{PackageBase: "stale", NumVotes: 3, LastModified: ago(400)},
		{PackageBase: "ancient-but-loved", NumVotes: 9999, LastModified: ago(2000)},
	}

	got := map[string]bool{}
	for _, m := range selectSeed(meta, "", 0, 365, now) {
		got[m.PackageBase] = true
	}
	if !got["fresh"] || !got["edge"] {
		t.Errorf("window dropped a package inside it: %v", got)
	}
	if got["stale"] || got["ancient-but-loved"] {
		t.Errorf("window kept a package outside it: %v", got)
	}

	// -top is additive: the popular package returns even though nothing about
	// it has changed inside the window.
	got = map[string]bool{}
	for _, m := range selectSeed(meta, "", 1, 365, now) {
		got[m.PackageBase] = true
	}
	if !got["ancient-but-loved"] {
		t.Errorf("-top did not re-add the most-voted base: %v", got)
	}
}

// TestSelectSeedWindowIsVotesOrdered pins the ordering the fetch budget relies
// on. -budget spends on the front of the seed, so if this is not votes-first a
// bounded run scans an arbitrary sample instead of the packages people install.
func TestSelectSeedWindowIsVotesOrdered(t *testing.T) {
	now := time.Now()
	var meta []metaPackage
	for i, n := range []string{"few", "many", "some"} {
		meta = append(meta, metaPackage{
			PackageBase: n, NumVotes: []int{1, 100, 10}[i], LastModified: now.Unix(),
		})
	}
	var got []string
	for _, m := range selectSeed(meta, "", 0, 365, now) {
		got = append(got, m.PackageBase)
	}
	if want := []string{"many", "some", "few"}; !slices.Equal(got, want) {
		t.Errorf("selectSeed = %v, want %v", got, want)
	}
}

// TestScanAllReusesUnchanged is the property the whole corpus rests on: a base
// whose LastModified has not moved is served from state, without a fetch. If
// this regresses the nightly run tries to download 47,000 snapshots.
func TestScanAllReusesUnchanged(t *testing.T) {
	seed := []metaPackage{{
		PackageBase: "demo", Version: "2.0-1", Description: "now with more votes",
		NumVotes: 99, LastModified: 1000,
	}}
	prev := map[string]stateRecord{"demo": {
		Base: "demo", LastModified: 1000, Grade: "B",
		Findings: []rules.Finding{{RuleID: "PB101"}},
		Drift:    []string{"a note from the run that saw it change"},
		Rules:    rulesFingerprint(),
	}}

	// cache points nowhere: a fetch would fail, so a passing test is proof
	// none was attempted.
	results, next := scanAll(seed, filepath.Join(t.TempDir(), "absent"), 1, 0, prev)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	r := results[0]
	if r.Grade != "B" || len(r.Findings) != 1 {
		t.Errorf("reused result lost its lint output: %+v", r)
	}
	if len(r.Drift) != 1 {
		t.Errorf("reused result lost its drift note: %+v", r.Drift)
	}
	// Metadata is free every run, so it refreshes even when the lint does not.
	if r.Votes != 99 || r.Version != "2.0-1" || r.Description != "now with more votes" {
		t.Errorf("reused result kept stale metadata: %+v", r)
	}
	if next["demo"].LastModified != 1000 || next["demo"].Grade != "B" {
		t.Errorf("state lost the reused record: %+v", next["demo"])
	}
}

// TestScanAllRescansOnRuleChange pins the other half of the reuse bargain: a
// record produced under a different rule registry is stale even though the
// PKGBUILD has not changed. The snapshot is planted in the cache, so the
// re-lint needs no network — which is also how a real registry bump refreshes
// most of the corpus for free.
func TestScanAllRescansOnRuleChange(t *testing.T) {
	cache := t.TempDir()
	dir := filepath.Join(cache, "snapshots", "demo@1000")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pkgbuild := "pkgname=demo\npkgver=1.0\npkgrel=1\npkgdesc='A demonstration tool'\n" +
		"arch=('any')\nurl='https://example.com'\nlicense=('MIT')\n"
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}

	seed := []metaPackage{{PackageBase: "demo", LastModified: 1000}}
	prev := map[string]stateRecord{"demo": {
		Base: "demo", LastModified: 1000, Grade: "F",
		Findings: []rules.Finding{{RuleID: "PB000", Message: "from a previous ruleset"}},
		Rules:    "0000000000000000", // not the current registry
	}}

	results, next := scanAll(seed, cache, 1, 0, prev)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	for _, f := range results[0].Findings {
		if f.RuleID == "PB000" {
			t.Errorf("stale findings survived the registry change: %+v", results[0].Findings)
		}
	}
	if results[0].Grade == "F" && len(results[0].Findings) == 1 {
		t.Errorf("result was reused despite the registry change: %+v", results[0])
	}
	if got := next["demo"].Rules; got != rulesFingerprint() {
		t.Errorf("refreshed record carries fingerprint %q, want the current registry's", got)
	}
}

// TestScanAllBudget pins how a bounded run divides the corpus. Bases past the
// budget must not be fetched, must keep their last known grade if they have
// one, and must keep their old LastModified so a later run picks them up.
func TestScanAllBudget(t *testing.T) {
	seed := []metaPackage{
		{PackageBase: "unchanged", NumVotes: 30, LastModified: 1000},
		{PackageBase: "known", NumVotes: 20, LastModified: 2000},
		{PackageBase: "new", NumVotes: 10, LastModified: 3000},
	}
	prev := map[string]stateRecord{
		"unchanged": {Base: "unchanged", LastModified: 1000, Grade: "A", Rules: rulesFingerprint()},
		// Changed since it was last scanned, so it is work — but the budget is
		// zero, so it renders at its old grade instead.
		"known": {Base: "known", LastModified: 1, Grade: "D", Rules: rulesFingerprint()},
	}

	// One fetch allowed against two candidates. "unchanged" is not a candidate
	// at all — it is reused — so the slot goes to "known", the more-voted of
	// the two, and "new" waits for a later run.
	results, next := scanAll(seed, filepath.Join(t.TempDir(), "absent"), 1, 1, prev)
	got := map[string]string{}
	for _, r := range results {
		got[r.Name] = r.Grade
	}
	if got["unchanged"] != "A" {
		t.Errorf("unchanged base was not reused: %v", got)
	}
	// "known" was the one scan the budget allowed; the fetch fails against an
	// absent cache, which is the recorded outcome.
	if _, ok := got["known"]; !ok {
		t.Errorf("budgeted base was dropped: %v", got)
	}
	if _, ok := got["new"]; ok {
		t.Errorf("never-scanned base past the budget should not render: %v", got)
	}
	// A failed scan must not be persisted, or the next run would treat the
	// failure as this snapshot's answer and never retry it.
	if next["known"].LastModified != 1 {
		t.Errorf("failed scan overwrote the record: %+v", next["known"])
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

// TestDecodeMetaCoMaintainers pins the field's spelling against the dump's.
// metaPackage carries no json tags, so a rename on either side would not fail
// to decode — it would silently turn every co-maintainer into nobody, and
// nothing else in the build would notice.
func TestDecodeMetaCoMaintainers(t *testing.T) {
	meta, err := decodeMeta(strings.NewReader(
		`[{"PackageBase":"a","Maintainer":"m","CoMaintainers":["b","c"]},{"PackageBase":"lone"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != 2 || !slices.Equal(meta[0].CoMaintainers, []string{"b", "c"}) {
		t.Errorf("decodeMeta = %+v, want co-maintainers [b c]", meta)
	}
	// The dump omits the key entirely when there are none; that must stay the
	// zero value, not an error and not an empty-but-allocated slice the JSON
	// output would then render as "co_maintainers": [].
	if meta[1].CoMaintainers != nil {
		t.Errorf("absent CoMaintainers decoded to %#v, want nil", meta[1].CoMaintainers)
	}
}
