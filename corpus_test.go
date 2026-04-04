//go:build corpus

package sdhash

// Corpus validation test index
//
// I. Reference corpus — stream mode
// └── 00010000  Full corpus stream digest validation
//
// II. Reference corpus — DD mode
// └── 00020000  Full corpus DD digest validation

import (
	"encoding/csv"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// loadReferenceCSV opens the CSV file at path, parses it, and returns a map
// from filename (column 0) to hash string (column 1). The header row is
// skipped. t.Fatalf is called on any I/O or parse error.
func loadReferenceCSV(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("loadReferenceCSV: cannot open %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("loadReferenceCSV: close %s: %v", path, err)
		}
	}()

	r := csv.NewReader(f)
	r.FieldsPerRecord = 2

	// Skip header row
	if _, err := r.Read(); err != nil {
		t.Fatalf("loadReferenceCSV: cannot read header from %s: %v", path, err)
	}

	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("loadReferenceCSV: cannot parse %s: %v", path, err)
	}

	m := make(map[string]string, len(records))
	for _, rec := range records {
		m[rec[0]] = rec[1]
	}
	return m
}

// loadCategoryRef loads the reference map for a single category. It first
// tries the single-file form (e.g. corpus_stream_random.csv). If that file
// does not exist it falls back to the split form (_a / _b), merging both
// halves into one map. This handles categories whose per-category CSV still
// exceeded GitHub's 50 MB warning threshold and were split further.
func loadCategoryRef(t *testing.T, path string) map[string]string {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return loadReferenceCSV(t, path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loadCategoryRef: stat %s: %v", path, err)
	}

	// Single file absent — try _a / _b split
	base := strings.TrimSuffix(path, ".csv")
	pathA := base + "_a.csv"
	pathB := base + "_b.csv"

	ma := loadReferenceCSV(t, pathA)
	mb := loadReferenceCSV(t, pathB)

	for k, v := range mb {
		ma[k] = v
	}
	return ma
}

// corpusWorkItem holds everything needed to compute a hash for one file.
// It is produced sequentially (preserving seedRng consumption order) and
// consumed concurrently by the worker pool.
type corpusWorkItem struct {
	filename string
	data     []byte
	catName  string
}

// corpusResult holds the outcome of hashing one work item.
// The index field ties it back to the original ordered position so Phase 3
// can iterate results in deterministic order without any sorting.
type corpusResult struct {
	index    int
	filename string
	digest   string
	density  float64
	dataLen  int
	err      error
}

// runCorpusValidation contains the shared three-phase validation loop used by
// both stream and DD corpus tests. Each call gets its own seedRng derived from
// corpusMasterSeed, so the two test functions remain independent.
//
//   - mode      — log/error prefix string ("stream" or "dd")
//   - csvPrefix — CSV filename prefix ("corpus_stream" or "corpus_dd")
//   - computeFn — takes a factory and returns the computed digest
func runCorpusValidation(t *testing.T, mode string, csvPrefix string, computeFn func(SdbfFactory) (Sdbf, error)) {
	t.Helper()

	seedRng := rand.New(rand.NewPCG(uint64(corpusMasterSeed), 0))

	totalChecked := 0
	totalMismatches := 0

	for _, cat := range corpusCategories() {
		ref := loadCategoryRef(t, fmt.Sprintf("testdata/%s_%s.csv", csvPrefix, cat.name))
		t.Logf("%s: %s: loaded %d reference entries", mode, cat.name, len(ref))

		lo, hi := corpusMinSize, corpusMaxSize
		if cat.customMinSize > 0 {
			lo = cat.customMinSize
		}
		if cat.customMaxSize > 0 {
			hi = cat.customMaxSize
		}
		n := corpusFilesPerType
		if cat.count > 0 {
			n = cat.count
		}

		sizes := generateSizes(seedRng, n, lo, hi)

		// ------------------------------------------------------------------
		// Phase 1 — Sequential: consume seedRng and generate data.
		// No hash computation here; we only collect work items.
		// ------------------------------------------------------------------
		workItems := make([]corpusWorkItem, 0, len(sizes))
		for i, size := range sizes {
			fileSeed := int64(seedRng.Uint64())
			filename := fmt.Sprintf("%s/%s_%06d_%d.bin", cat.name, cat.name, i, size)

			rng := rand.New(rand.NewPCG(uint64(fileSeed), 0))
			data := cat.gen(rng, size)

			if len(data) < MinFileSize {
				continue
			}

			workItems = append(workItems, corpusWorkItem{
				filename: filename,
				data:     data,
				catName:  cat.name,
			})
		}

		// ------------------------------------------------------------------
		// Phase 2 — Parallel: compute hashes with a bounded worker pool.
		// Each goroutine writes to its own index in results; no mutex needed.
		// ------------------------------------------------------------------
		results := make([]corpusResult, len(workItems))

		sem := make(chan struct{}, runtime.NumCPU())
		var wg sync.WaitGroup

		for idx, item := range workItems {
			wg.Add(1)
			sem <- struct{}{} // acquire a slot
			go func(idx int, item corpusWorkItem) {
				defer wg.Done()
				defer func() { <-sem }() // release slot

				res := corpusResult{
					index:    idx,
					filename: item.filename,
					dataLen:  len(item.data),
				}

				factory, err := New(item.data)
				if err != nil {
					//goland:noinspection GoErrorStringFormat
					res.err = fmt.Errorf("New error: %w", err)
					results[idx] = res
					return
				}
				sd, err := computeFn(factory)
				if err != nil {
					res.err = fmt.Errorf("compute error: %w", err)
					results[idx] = res
					return
				}
				res.digest = strings.TrimRight(sd.String(), "\r\n")
				res.density = sd.FeatureDensity()
				results[idx] = res
			}(idx, item)
		}

		wg.Wait()

		// ------------------------------------------------------------------
		// Phase 3 — Sequential: compare results against the reference CSV.
		// Iterating in original order preserves deterministic test output.
		// ------------------------------------------------------------------
		for _, res := range results {
			if res.err != nil {
				t.Errorf("%s: %s: %v", mode, res.filename, res.err)
				continue
			}

			totalChecked++
			if totalChecked%10000 == 0 {
				t.Logf("%s: checked %d files so far...", mode, totalChecked)
			}

			want, ok := ref[res.filename]
			if !ok {
				t.Errorf("%s: %s: not found in reference CSV", mode, res.filename)
				totalMismatches++
				continue
			}

			if res.digest != want {
				wantPrefix := want
				if len(wantPrefix) > 80 {
					wantPrefix = wantPrefix[:80]
				}
				gotPrefix := res.digest
				if len(gotPrefix) > 80 {
					gotPrefix = gotPrefix[:80]
				}
				t.Errorf("%s: %s: digest mismatch\n  want: %s\n  got:  %s\n  size=%d density=%g",
					mode, res.filename, wantPrefix, gotPrefix, res.dataLen, res.density)
				totalMismatches++
			}
		}
	}

	t.Logf("%s: checked %d files, %d mismatches", mode, totalChecked, totalMismatches)
}

// =========================================================================
// I. Reference corpus — stream mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Full corpus stream digest validation
// ---------------------------------------------------------------------------

func TestCorpus_StreamMode(t *testing.T) {
	runCorpusValidation(t, "stream", "corpus_stream", func(f SdbfFactory) (Sdbf, error) {
		return f.Compute()
	})
}

// =========================================================================
// II. Reference corpus — DD mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00020000  Full corpus DD digest validation
// ---------------------------------------------------------------------------

func TestCorpus_DDMode(t *testing.T) {
	runCorpusValidation(t, "dd", "corpus_dd", func(f SdbfFactory) (Sdbf, error) {
		return f.WithBlockSize(corpusDDBlockSize).Compute()
	})
}
