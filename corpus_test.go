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
	"strings"
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

// =========================================================================
// I. Reference corpus — stream mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00010000  Full corpus stream digest validation
// ---------------------------------------------------------------------------

func TestCorpus_StreamMode(t *testing.T) {
	seedRng := rand.New(rand.NewPCG(uint64(corpusMasterSeed), 0))

	totalChecked := 0
	totalMismatches := 0

	for _, cat := range corpusCategories() {
		ref := loadCategoryRef(t, fmt.Sprintf("testdata/corpus_stream_%s.csv", cat.name))
		t.Logf("stream: %s: loaded %d reference entries", cat.name, len(ref))

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

		for i, size := range sizes {
			fileSeed := int64(seedRng.Uint64())
			filename := fmt.Sprintf("%s/%s_%06d_%d.bin", cat.name, cat.name, i, size)

			rng := rand.New(rand.NewPCG(uint64(fileSeed), 0))
			data := cat.gen(rng, size)

			if len(data) < MinFileSize {
				continue
			}

			factory, err := CreateSdbfFromBytes(data)
			if err != nil {
				t.Errorf("stream: %s: CreateSdbfFromBytes error: %v", filename, err)
				continue
			}
			sd, err := factory.Compute()
			if err != nil {
				t.Errorf("stream: %s: Compute error: %v", filename, err)
				continue
			}
			got := strings.TrimRight(sd.String(), "\r\n")

			totalChecked++
			if totalChecked%10000 == 0 {
				t.Logf("stream: checked %d files so far...", totalChecked)
			}

			want, ok := ref[filename]
			if !ok {
				t.Errorf("stream: %s: not found in reference CSV", filename)
				totalMismatches++
				continue
			}

			if got != want {
				wantPrefix := want
				if len(wantPrefix) > 80 {
					wantPrefix = wantPrefix[:80]
				}
				gotPrefix := got
				if len(gotPrefix) > 80 {
					gotPrefix = gotPrefix[:80]
				}
				t.Errorf("stream: %s: digest mismatch\n  want: %s\n  got:  %s\n  size=%d density=%g",
					filename, wantPrefix, gotPrefix, len(data), sd.FeatureDensity())
				totalMismatches++
			}
		}
	}

	t.Logf("stream: checked %d files, %d mismatches", totalChecked, totalMismatches)
}

// =========================================================================
// II. Reference corpus — DD mode
// =========================================================================

// ---------------------------------------------------------------------------
// 00020000  Full corpus DD digest validation
// ---------------------------------------------------------------------------

func TestCorpus_DDMode(t *testing.T) {
	seedRng := rand.New(rand.NewPCG(uint64(corpusMasterSeed), 0))

	totalChecked := 0
	totalMismatches := 0

	for _, cat := range corpusCategories() {
		ref := loadCategoryRef(t, fmt.Sprintf("testdata/corpus_dd_%s.csv", cat.name))
		t.Logf("dd: %s: loaded %d reference entries", cat.name, len(ref))

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

		for i, size := range sizes {
			fileSeed := int64(seedRng.Uint64())
			filename := fmt.Sprintf("%s/%s_%06d_%d.bin", cat.name, cat.name, i, size)

			rng := rand.New(rand.NewPCG(uint64(fileSeed), 0))
			data := cat.gen(rng, size)

			if len(data) < MinFileSize {
				continue
			}

			factory, err := CreateSdbfFromBytes(data)
			if err != nil {
				t.Errorf("dd: %s: CreateSdbfFromBytes error: %v", filename, err)
				continue
			}
			sd, err := factory.WithBlockSize(corpusDDBlockSize).Compute()
			if err != nil {
				t.Errorf("dd: %s: Compute error: %v", filename, err)
				continue
			}
			got := strings.TrimRight(sd.String(), "\r\n")

			totalChecked++
			if totalChecked%10000 == 0 {
				t.Logf("dd: checked %d files so far...", totalChecked)
			}

			want, ok := ref[filename]
			if !ok {
				t.Errorf("dd: %s: not found in reference CSV", filename)
				totalMismatches++
				continue
			}

			if got != want {
				wantPrefix := want
				if len(wantPrefix) > 80 {
					wantPrefix = wantPrefix[:80]
				}
				gotPrefix := got
				if len(gotPrefix) > 80 {
					gotPrefix = gotPrefix[:80]
				}
				t.Errorf("dd: %s: digest mismatch\n  want: %s\n  got:  %s\n  size=%d density=%g",
					filename, wantPrefix, gotPrefix, len(data), sd.FeatureDensity())
				totalMismatches++
			}
		}
	}

	t.Logf("dd: checked %d files, %d mismatches", totalChecked, totalMismatches)
}
