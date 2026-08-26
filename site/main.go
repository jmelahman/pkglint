// Command site generates the static AUR report-card website.
//
// It downloads the AUR metadata dump, selects a seed set of packages
// (a maintainer's packages plus the top-N by votes), fetches each package
// base's snapshot tarball (cached by LastModified), runs pkglint in-process,
// and renders a static site: an index, a page per package, a page per rule,
// per-package SVG badges, and results.json.
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	Err          string          `json:"error,omitempty"`
	LastModified int64           `json:"last_modified"`
}

func main() {
	out := flag.String("out", "public", "output directory for the generated site")
	cache := flag.String("cache", ".cache", "cache directory for downloads")
	maintainer := flag.String("maintainer", "", "always include this maintainer's packages")
	top := flag.Int("top", 500, "also include the top-N packages by votes")
	jobs := flag.Int("jobs", 2, "concurrent snapshot fetches")
	limit := flag.Int("limit", 0, "hard cap on packages scanned (0 = no cap), for smoke tests")
	flag.Parse()

	if err := run(*out, *cache, *maintainer, *top, *jobs, *limit); err != nil {
		log.Fatal(err)
	}
}

func run(out, cache, maintainer string, top, jobs, limit int) error {
	for _, dir := range []string{out, cache, filepath.Join(out, "package"), filepath.Join(out, "rules"), filepath.Join(out, "badge")} {
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

	seed := selectSeed(meta, maintainer, top)
	if limit > 0 && len(seed) > limit {
		seed = seed[:limit]
	}
	log.Printf("scanning %d package bases (maintainer=%q top=%d)", len(seed), maintainer, top)

	results := scanAll(seed, cache, jobs)

	sort.Slice(results, func(i, j int) bool {
		if results[i].Grade != results[j].Grade {
			return results[i].Grade > results[j].Grade // worst first
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
		if err := os.WriteFile(filepath.Join(out, "badge", r.Name+".svg"), []byte(badgeSVG(r.Grade)), 0o644); err != nil {
			return err
		}
	}
	log.Printf("site written to %s", out)
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
	var meta []metaPackage
	if err := json.NewDecoder(gz).Decode(&meta); err != nil {
		return nil, err
	}
	return meta, nil
}

// selectSeed picks one representative per package base: everything by
// maintainer, plus the top-N bases by votes.
func selectSeed(meta []metaPackage, maintainer string, top int) []metaPackage {
	byBase := map[string]metaPackage{}
	for _, m := range meta {
		cur, ok := byBase[m.PackageBase]
		if !ok || m.NumVotes > cur.NumVotes {
			byBase[m.PackageBase] = m
		}
	}
	bases := make([]metaPackage, 0, len(byBase))
	for _, m := range byBase {
		bases = append(bases, m)
	}
	sort.Slice(bases, func(i, j int) bool { return bases[i].NumVotes > bases[j].NumVotes })

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
	// The top-N most voted bases; overlap with the maintainer set is a no-op.
	for i := 0; i < len(bases) && i < top; i++ {
		add(bases[i])
	}
	return seed
}

func scanAll(seed []metaPackage, cache string, jobs int) []siteResult {
	results := make([]siteResult, len(seed))
	var wg sync.WaitGroup
	sem := make(chan struct{}, jobs)
	for i, m := range seed {
		wg.Add(1)
		go func(i int, m metaPackage) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = scanOne(m, cache)
		}(i, m)
	}
	wg.Wait()
	return results
}

func scanOne(m metaPackage, cache string) siteResult {
	res := siteResult{
		Name: m.PackageBase, Base: m.PackageBase, Version: m.Version,
		Description: m.Description, Votes: m.NumVotes, LastModified: m.LastModified,
		Findings: []rules.Finding{},
	}
	if m.Maintainer != nil {
		res.Maintainer = *m.Maintainer
	}
	dir, err := fetchSnapshot(m, cache)
	if err != nil {
		res.Grade, res.Err = "?", err.Error()
		return res
	}
	pkg, err := pkgbuild.Load(dir)
	if err != nil {
		res.Grade, res.Err = "?", err.Error()
		return res
	}
	res.Findings = rules.Run(pkg, nil)
	if res.Findings == nil {
		res.Findings = []rules.Finding{}
	}
	// Strip the cache prefix from finding paths.
	for i := range res.Findings {
		res.Findings[i].Path = strings.TrimPrefix(res.Findings[i].Path, dir+string(filepath.Separator))
	}
	res.Grade = report.Grade(res.Findings)
	return res
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
	if _, err := io.Copy(f, resp.Body); err != nil {
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

// badgeSVG renders a shields.io-style flat badge for a grade.
func badgeSVG(grade string) string {
	colors := map[string]string{
		"A": "#4c1", "B": "#97ca00", "C": "#dfb317", "D": "#fe7d37", "F": "#e05d44", "?": "#9f9f9f",
	}
	color, ok := colors[grade]
	if !ok {
		color = "#9f9f9f"
	}
	const label, labelW, gradeW = "pkglint", 50, 24
	total := labelW + gradeW
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="%d" height="20" fill="#555"/><rect x="%d" width="%d" height="20" fill="%s"/><rect width="%d" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="%d" y="14">%s</text><text x="%d" y="14" font-weight="bold">%s</text></g></svg>`,
		total, label, grade, total, labelW, labelW, gradeW, color, total,
		labelW/2, label, labelW+gradeW/2, grade)
}
