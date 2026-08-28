// Command site generates the static AUR report-card website.
//
// It downloads the AUR metadata dump, selects a seed set of packages (every
// base modified recently, plus a maintainer's packages and the top-N by
// votes), fetches each package base's snapshot tarball (cached by
// LastModified), runs pkglint in-process, and renders a static site: an index,
// a page per package, a page per rule, alphabetical roster pages, per-package
// SVG badges, a sitemap, and results.json.
//
// The seed runs to tens of thousands of bases, which is more than one run can
// fetch: see state.go for the checked-in scan state that makes that tractable,
// and -budget for the cap on what a single run downloads.
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jmelahman/pkglint/internal/pkgbuild"
	"github.com/jmelahman/pkglint/internal/report"
	"github.com/jmelahman/pkglint/internal/rules"
)

const (
	metaURL     = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz"
	snapshotURL = "https://aur.archlinux.org/cgit/aur.git/snapshot/%s.tar.gz"
	userAgent   = "pkglint-site (+https://github.com/jmelahman/pkglint)"

	maxSnapshotFile  = 1 << 20 // per-file extraction cap
	maxSnapshotFiles = 64
)

// Ceilings on untrusted downloads. These are DoS backstops, not correctness
// limits: they exist so a hostile, MITM'd, or corrupt response cannot fill the
// CI disk or exhaust memory. Both sit far above real data, measured
// 2026-08-26: packages-meta-ext-v1.json.gz was 14,002,064 B (13.4 MiB)
// compressed and 72,758,642 B (69.4 MiB) decompressed, and package snapshot
// tarballs are kilobytes. They are vars, not consts, so tests can lower them.
var (
	// maxDownloadBytes caps any single HTTP body written to disk — ~19x the
	// real metadata dump, and orders of magnitude above any snapshot.
	maxDownloadBytes int64 = 256 << 20 // 256 MiB

	// maxMetaDecompressed caps the decompressed metadata fed to the JSON
	// decoder, guarding against a gzip bomb — ~14x the real dump. Truncating a
	// legitimate dump would surface as a JSON decode error, so keep the
	// headroom generous.
	maxMetaDecompressed int64 = 1 << 30 // 1 GiB
)

type metaPackage struct {
	Name         string
	PackageBase  string
	Version      string
	Description  string
	URL          string
	Maintainer   *string
	NumVotes     int
	Popularity   float64
	LastModified int64
}

type siteResult struct {
	Name         string          `json:"name"`
	Base         string          `json:"base"`
	Version      string          `json:"version"`
	Description  string          `json:"description"`
	Maintainer   string          `json:"maintainer"`
	Votes        int             `json:"votes"`
	Grade        string          `json:"grade"`
	Findings     []rules.Finding `json:"findings"`
	Drift        []string        `json:"drift,omitempty"` // provenance drift vs. the previous scan
	Err          string          `json:"error,omitempty"`
	LastModified int64           `json:"last_modified"`
}

func main() {
	out := flag.String("out", "public", "output directory for the generated site")
	cache := flag.String("cache", ".cache", "cache directory for downloads")
	state := flag.String("state", "data/state.jsonl", "checked-in scan state; bases unchanged since it was written are not refetched")
	maintainer := flag.String("maintainer", "", "always include this maintainer's packages")
	top := flag.Int("top", 0, "also include the top-N packages by votes (0 = none)")
	since := flag.Int("since-days", 90, "include every package base modified within the last N days (0 = none)")
	budget := flag.Int("budget", 0, "max snapshot fetches this run (0 = no cap); bases past it keep their last known result")
	jobs := flag.Int("jobs", 2, "concurrent snapshot fetches")
	limit := flag.Int("limit", 0, "hard cap on packages scanned (0 = no cap), for smoke tests")
	flag.Parse()

	if err := run(*out, *cache, *state, *maintainer, *top, *since, *budget, *jobs, *limit); err != nil {
		log.Fatal(err)
	}
}

func run(out, cache, statePath, maintainer string, top, since, budget, jobs, limit int) error {
	for _, dir := range []string{out, cache, filepath.Join(out, "package"), filepath.Join(out, "rules"), filepath.Join(out, "badge"), filepath.Join(out, "roster")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// Serve the tree verbatim on GitHub Pages: no Jekyll processing, and don't
	// drop paths beginning with an underscore.
	if err := os.WriteFile(filepath.Join(out, ".nojekyll"), nil, 0o644); err != nil {
		return err
	}

	meta, err := loadMeta(cache)
	if err != nil {
		return err
	}
	log.Printf("metadata: %d packages", len(meta))

	seed := selectSeed(meta, maintainer, top, since, time.Now())
	if limit > 0 && len(seed) > limit {
		seed = seed[:limit]
	}
	log.Printf("seed: %d package bases (maintainer=%q top=%d since=%dd)", len(seed), maintainer, top, since)

	prev, err := loadState(statePath)
	if err != nil {
		return fmt.Errorf("load scan state: %w", err)
	}
	results, state := scanAll(seed, cache, jobs, budget, prev)
	if err := saveState(statePath, state); err != nil {
		return err
	}

	// Votes order, not worst-grade-first: the roster's server-rendered slice is
	// its head, so this decides which packages a visitor sees before any
	// filtering. The most-installed packages are the ones worth showing there —
	// sorted by grade the head would be an unbroken run of Fs from packages
	// nobody has heard of. Votes also move far more slowly than grades do,
	// which keeps the committed output's nightly diff small.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Votes != results[j].Votes {
			return results[i].Votes > results[j].Votes
		}
		return results[i].Name < results[j].Name
	})

	if err := writeJSON(filepath.Join(out, "results.json"), results); err != nil {
		return err
	}
	if err := renderSite(out, results); err != nil {
		return err
	}
	for _, r := range results {
		// selectSeed already filtered these; re-check at the write site so a
		// name arriving by any other route still cannot escape out/badge.
		if !safeBase(r.Name) {
			log.Printf("skipping badge for unsafe name %q", r.Name)
			continue
		}
		if err := os.WriteFile(filepath.Join(out, "badge", r.Name+".svg"), []byte(badgeSVG(r.Grade)), 0o644); err != nil {
			return err
		}
	}
	keep := make(map[string]bool, len(results))
	for _, r := range results {
		keep[r.Name] = true
	}
	ruleIDs := map[string]bool{"index": true}
	for _, r := range rules.Registry() {
		ruleIDs[r.ID] = true
	}
	// A letter empties out when its last package leaves the corpus, so the
	// shards are pruned on the same rule as everything else.
	shardKeys := map[string]bool{"index": true}
	for _, s := range groupShards(results) {
		shardKeys[s.Key] = true
	}
	for _, p := range []struct {
		dir, ext string
		keep     map[string]bool
	}{
		{filepath.Join(out, "package"), ".html", keep},
		{filepath.Join(out, "badge"), ".svg", keep},
		{filepath.Join(out, "rules"), ".html", ruleIDs},
		{filepath.Join(out, "roster"), ".html", shardKeys},
	} {
		if err := prune(p.dir, p.ext, p.keep); err != nil {
			return err
		}
	}

	log.Printf("site written to %s", out)
	return nil
}

// prune deletes generated pages that this run did not write. Without it a
// package that drops out of the seed keeps its page on the site for ever,
// served against whatever the current stylesheet happens to be — a stale grade
// for a package no longer being scanned is worse than no page at all.
func prune(dir, ext string, keep map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ext) || keep[strings.TrimSuffix(name, ext)] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}
		log.Printf("removed stale %s", filepath.Join(dir, name))
	}
	return nil
}

// loadMeta downloads (or reuses a same-day cached copy of) the AUR metadata
// dump.
func loadMeta(cache string) ([]metaPackage, error) {
	path := filepath.Join(cache, "packages-meta-ext-v1.json.gz")
	if st, err := os.Stat(path); err != nil || time.Since(st.ModTime()) > 20*time.Hour {
		if err := download(metaURL, path); err != nil {
			return nil, fmt.Errorf("download metadata dump: %w", err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return decodeMeta(gz)
}

// decodeMeta decodes the metadata JSON from r, reading at most
// maxMetaDecompressed bytes so a gzip bomb cannot exhaust memory. A truncated
// stream surfaces as a JSON decode error, which is the safe failure mode.
func decodeMeta(r io.Reader) ([]metaPackage, error) {
	var meta []metaPackage
	if err := json.NewDecoder(io.LimitReader(r, maxMetaDecompressed)).Decode(&meta); err != nil {
		return nil, err
	}
	return meta, nil
}

// baseRe matches the shape the AUR already constrains package bases to: a
// leading alphanumeric followed by alphanumerics and @._+- only.
var baseRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+-]*$`)

// safeBase reports whether an AUR package base is safe to use as a single path
// component and URL segment. Anything else (slashes, "..", leading dot,
// control characters) is treated as hostile metadata and dropped: the base
// becomes a filename under the published site tree, so the generator must not
// assume upstream validated it.
func safeBase(name string) bool {
	return name != ".." && baseRe.MatchString(name) && !strings.Contains(name, "..")
}

// selectSeed picks one representative per package base: everything by
// maintainer, everything modified within the last sinceDays, plus the top-N
// bases by votes. Bases with unsafe names are dropped here, the single choke
// point, so no unsafe name reaches scanAll, results.json, the rendered links,
// or any output filename.
//
// The result is ordered by votes, which is what makes a partial run coherent:
// -budget spends on the front of this slice, so an incomplete corpus is the
// most-installed packages rather than an arbitrary sample.
func selectSeed(meta []metaPackage, maintainer string, top, sinceDays int, now time.Time) []metaPackage {
	byBase := map[string]metaPackage{}
	for _, m := range meta {
		if !safeBase(m.PackageBase) {
			log.Printf("skipping package base with unsafe name %q", m.PackageBase)
			continue
		}
		cur, ok := byBase[m.PackageBase]
		if !ok || m.NumVotes > cur.NumVotes {
			byBase[m.PackageBase] = m
		}
	}
	bases := make([]metaPackage, 0, len(byBase))
	for _, m := range byBase {
		bases = append(bases, m)
	}
	// Votes alone do not order this set: they come out of a map, sort.Slice is
	// not stable, and the AUR has long runs of bases on identical counts. Ties
	// at the top-N cutoff then fall differently on every run, so a package
	// drifts in and out of the site — its page and badge appearing, 404ing, and
	// reappearing — over input that never changed. Break on the name.
	sort.Slice(bases, func(i, j int) bool {
		if bases[i].NumVotes != bases[j].NumVotes {
			return bases[i].NumVotes > bases[j].NumVotes
		}
		return bases[i].PackageBase < bases[j].PackageBase
	})

	var seed []metaPackage
	seen := map[string]bool{}
	add := func(m metaPackage) {
		if !seen[m.PackageBase] {
			seen[m.PackageBase] = true
			seed = append(seed, m)
		}
	}
	if maintainer != "" {
		for _, m := range bases {
			if m.Maintainer != nil && *m.Maintainer == maintainer {
				add(m)
			}
		}
	}
	// Everything touched inside the window. A base the AUR has not seen an
	// update to in a year is not what the report card is for: its PKGBUILD is
	// as likely to be abandoned as clean, and scanning it costs the same as
	// scanning one somebody still installs.
	if sinceDays > 0 {
		cutoff := now.AddDate(0, 0, -sinceDays).Unix()
		for _, m := range bases {
			if m.LastModified >= cutoff {
				add(m)
			}
		}
	}
	// The top-N most voted bases; overlap with the sets above is a no-op. This
	// is what keeps a heavily-installed but long-stable package on the site
	// even though nothing about it has changed inside the window.
	for i := 0; i < len(bases) && i < top; i++ {
		add(bases[i])
	}
	return seed
}

// scanAll produces a result for every seed package and returns the updated
// scan state: prev with every freshly scanned base overwritten, so bases that
// drop out of the seed keep their history rather than being forgotten.
//
// Most of the corpus is not scanned on any given run. A base whose
// LastModified matches its state record cannot have changed, so its grade,
// findings and fingerprint are reused untouched — no snapshot fetch, no lint.
// What remains is split against budget up front, in seed order, rather than by
// letting goroutines race for it: the seed is votes-ordered, so deciding here
// means a bounded run spends on the most-installed packages and does so
// reproducibly.
func scanAll(seed []metaPackage, cache string, jobs, budget int, prev map[string]stateRecord) ([]siteResult, map[string]stateRecord) {
	results := make([]siteResult, len(seed))
	keep := make([]bool, len(seed))
	var todo []int
	var reused, stale, omitted int

	for i, m := range seed {
		rec, ok := prev[m.PackageBase]
		switch {
		// A record carrying an error is not fresh: the failure may have been a
		// transient fetch, and a base that is genuinely gone leaves the
		// metadata dump and so never reaches this loop again.
		case ok && rec.Err == "" && rec.LastModified == m.LastModified:
			results[i], keep[i] = resultFrom(m, rec), true
			reused++
		case budget > 0 && len(todo) >= budget:
			// Out of budget. A base seen before still has a real grade from a
			// real snapshot, so show it and leave its record's LastModified
			// where it was — that is what makes the next run pick it up. A base
			// never scanned has nothing to show, so it stays off the site until
			// a later run reaches it.
			if ok {
				results[i], keep[i] = resultFrom(m, rec), true
				stale++
			} else {
				omitted++
			}
		default:
			todo = append(todo, i)
			keep[i] = true
		}
	}

	states := make([]*stateRecord, len(seed))
	var wg sync.WaitGroup
	sem := make(chan struct{}, jobs)
	for _, i := range todo {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], states[i] = scanOne(seed[i], cache, prev)
		}(i)
	}
	wg.Wait()

	next := make(map[string]stateRecord, len(prev)+len(seed))
	maps.Copy(next, prev)
	for i, st := range states {
		if st != nil {
			next[seed[i].PackageBase] = *st
		}
	}

	kept := make([]siteResult, 0, len(seed))
	for i, ok := range keep {
		if ok {
			kept = append(kept, results[i])
		}
	}
	log.Printf("scanned %d, reused %d, stale %d, awaiting a later run %d (%d rendered)",
		len(todo), reused, stale, omitted, len(kept))
	return kept, next
}

// resultFrom rebuilds a result from a state record, refreshing everything the
// metadata dump carries. Votes and description are free on every run, so a
// package whose PKGBUILD has not changed still shows a current vote count.
func resultFrom(m metaPackage, rec stateRecord) siteResult {
	res := siteResult{
		Name: m.PackageBase, Base: m.PackageBase, Version: m.Version,
		Description: m.Description, Votes: m.NumVotes, LastModified: m.LastModified,
		Grade: rec.Grade, Findings: rec.Findings, Drift: rec.Drift, Err: rec.Err,
	}
	if m.Maintainer != nil {
		res.Maintainer = *m.Maintainer
	}
	if res.Findings == nil {
		res.Findings = []rules.Finding{}
	}
	return res
}

func scanOne(m metaPackage, cache string, prev map[string]stateRecord) (siteResult, *stateRecord) {
	res := siteResult{
		Name: m.PackageBase, Base: m.PackageBase, Version: m.Version,
		Description: m.Description, Votes: m.NumVotes, LastModified: m.LastModified,
		Findings: []rules.Finding{},
	}
	if m.Maintainer != nil {
		res.Maintainer = *m.Maintainer
	}
	// A failed scan is recorded but not persisted: writing it would pin the
	// record to this LastModified and stop the next run from retrying.
	dir, err := fetchSnapshot(m, cache)
	if err != nil {
		res.Grade, res.Err = "?", err.Error()
		return res, nil
	}
	pkg, err := pkgbuild.Load(dir)
	if err != nil {
		res.Grade, res.Err = "?", err.Error()
		return res, nil
	}
	cur := extractState(pkg, m.LastModified)
	res.Drift = driftNotes(prev[m.PackageBase].Fingerprint, cur)
	res.Findings = rules.Run(pkg, nil)
	if res.Findings == nil {
		res.Findings = []rules.Finding{}
	}
	// Strip the cache prefix from finding paths.
	for i := range res.Findings {
		res.Findings[i].Path = strings.TrimPrefix(res.Findings[i].Path, dir+string(filepath.Separator))
	}
	res.Grade = report.Grade(res.Findings)
	return res, &stateRecord{
		Base:         m.PackageBase,
		LastModified: m.LastModified,
		Grade:        res.Grade,
		Findings:     res.Findings,
		Drift:        res.Drift,
		Fingerprint:  cur,
	}
}

// fetchSnapshot downloads and extracts a package base's snapshot, cached by
// LastModified.
func fetchSnapshot(m metaPackage, cache string) (string, error) {
	dir := filepath.Join(cache, "snapshots", fmt.Sprintf("%s@%d", m.PackageBase, m.LastModified))
	if _, err := os.Stat(filepath.Join(dir, "PKGBUILD")); err == nil {
		return dir, nil
	}
	tarPath := dir + ".tar.gz"
	if err := download(fmt.Sprintf(snapshotURL, m.PackageBase), tarPath); err != nil {
		return "", err
	}
	defer os.Remove(tarPath)
	if err := extract(tarPath, dir); err != nil {
		return "", err
	}
	return dir, nil
}

// extract unpacks regular files from the snapshot tarball, flattening the
// single top-level directory and refusing anything odd.
func extract(tarPath, dir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	count := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if count++; count > maxSnapshotFiles {
			return fmt.Errorf("snapshot has too many files")
		}
		// Entries look like "<base>/PKGBUILD"; keep only the basename so
		// hostile paths cannot escape the target directory.
		name := filepath.Base(filepath.Clean(hdr.Name))
		if name == "." || name == ".." || strings.HasPrefix(name, "/") {
			continue
		}
		out, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, maxSnapshotFile)); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
}

// throttle spaces out requests so the AUR's rate limiting stays happy.
var throttle = time.NewTicker(500 * time.Millisecond)

func download(url, path string) error {
	resp, err := get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	// Read one byte past the ceiling so an over-long body is detected rather
	// than silently truncated into a "successful" download.
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err == nil && n > maxDownloadBytes {
		err = fmt.Errorf("download exceeded %d bytes: %s", maxDownloadBytes, url)
	}
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// get issues a throttled GET, retrying transient failures (429s and
// transport hiccups) with growing backoff and honoring Retry-After.
func get(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	backoff := []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second}
	var lastErr error
	for attempt := 0; ; attempt++ {
		<-throttle.C
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		switch {
		case err != nil:
			lastErr = err
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("GET %s: %s", url, resp.Status)
			if wait, err := time.ParseDuration(resp.Header.Get("Retry-After") + "s"); err == nil && attempt < len(backoff) {
				resp.Body.Close()
				time.Sleep(wait)
				continue
			}
			resp.Body.Close()
		default:
			resp.Body.Close()
			return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
		}
		if attempt >= len(backoff) {
			return nil, lastErr
		}
		time.Sleep(backoff[attempt])
	}
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// badgeSVG renders a flat badge for a grade, in the site's grade ramp so a
// letter means the same colour in a README as it does on the report card. The
// ramp is the report-card one, green through red, with "?" off it in grey.
//
// The badge keeps the familiar shields.io silhouette because that is what a
// README expects, but drops the gloss gradient and puts dark text on the
// coloured half — the ramp's middle is far too light to carry white. The
// charcoal label half is chosen to stay legible against both a white and a dark
// README background, since the badge has no control over where it lands.
func badgeSVG(grade string) string {
	const charcoal, ink, chalk = "#2b2b32", "#0a0a0c", "#f4f4f5"
	colors := map[string]string{
		"A": "#57b87e", "B": "#a3c265", "C": "#d8b04a", "D": "#e08a48", "F": "#e05a55", "?": "#898994",
	}
	color, ok := colors[grade]
	if !ok {
		color = colors["?"]
	}
	const label, labelW, gradeW = "pkglint", 50, 24
	total := labelW + gradeW
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="%d" height="20" fill="%s"/><rect x="%d" width="%d" height="20" fill="%s"/></g>
<g text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="%d" y="14" fill="%s">%s</text><text x="%d" y="14" fill="%s" font-weight="bold">%s</text></g></svg>`,
		total, label, grade, total, labelW, charcoal, labelW, gradeW, color,
		labelW/2, chalk, label, labelW+gradeW/2, ink, grade)
}
