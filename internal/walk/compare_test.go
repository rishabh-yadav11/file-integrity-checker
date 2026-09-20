package walk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

func mustScan(t *testing.T, root string, opts Options) []model.Entry {
	t.Helper()
	entries, err := Scan(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestCompareAllUnmodified(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Entries: mustScan(t, root, opts)}
	results, err := Compare(root, base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range results {
		if r.Kind != model.KindUnmodified {
			t.Errorf("%s: got %s, want unmodified (%v)", r.Path, r.Kind, r.Reasons)
		}
	}
}

func TestCompareModified(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Entries: mustScan(t, root, opts)}
	if err := os.WriteFile(filepath.Join(root, "a.log"), []byte("TAMPERED"), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := Compare(root, base, opts)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]model.Result{}
	for _, r := range results {
		byPath[r.Path] = r
	}
	mod, ok := byPath["a.log"]
	if !ok || mod.Kind != model.KindModified {
		t.Fatalf("a.log result = %+v, want modified", byPath["a.log"])
	}
	found := false
	for _, r := range mod.Reasons {
		if r == "hash" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected hash reason, got %v", mod.Reasons)
	}
}

func TestCompareNewAndMissing(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Entries: mustScan(t, root, opts)}
	if err := os.Remove(filepath.Join(root, "b.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "z.log"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := Compare(root, base, opts)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]model.ChangeKind{}
	for _, r := range results {
		kinds[r.Path] = r.Kind
	}
	if kinds["b.log"] != model.KindMissing {
		t.Errorf("b.log = %v, want missing", kinds["b.log"])
	}
	if kinds["z.log"] != model.KindNew {
		t.Errorf("z.log = %v, want new", kinds["z.log"])
	}
	if kinds["a.log"] != model.KindUnmodified {
		t.Errorf("a.log = %v, want unmodified", kinds["a.log"])
	}
}

func TestCompareAlgoMismatch(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	base := model.Baseline{Algorithm: model.AlgoSHA512}
	if _, err := Compare(root, base, Options{Algo: model.AlgoSHA256}); err == nil {
		t.Fatal("expected algorithm mismatch error")
	}
}

func TestDiffReasons(t *testing.T) {
	t.Parallel()
	now := time.Now()
	old := model.Entry{Path: "x", Hash: "h", Size: 10, Mode: 0o644, UID: 0, GID: 0, Mtime: now}
	tests := []struct {
		name     string
		mut      func(*model.Entry)
		wantPfx  string
		wantNone bool
	}{
		{"hash", func(e *model.Entry) { e.Hash = "different" }, "hash", false},
		{"size", func(e *model.Entry) { e.Size = 999 }, "size", false},
		{"mode", func(e *model.Entry) { e.Mode = 0o600 }, "mode", false},
		{"uid", func(e *model.Entry) { e.UID = 99 }, "uid", false},
		{"gid", func(e *model.Entry) { e.GID = 99 }, "gid", false},
		{"mtime", func(e *model.Entry) { e.Mtime = now.Add(time.Minute) }, "mtime", false},
		{"clean", func(e *model.Entry) {}, "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cur := old
			tt.mut(&cur)
			reasons := DiffEntries(cur, old)
			if tt.wantNone {
				if len(reasons) != 0 {
					t.Fatalf("expected no reasons, got %v", reasons)
				}
				return
			}
			found := false
			for _, r := range reasons {
				if strings.HasPrefix(r, tt.wantPfx) {
					found = true
				}
			}
			if !found {
				t.Fatalf("reasons %v missing prefix %q", reasons, tt.wantPfx)
			}
		})
	}
}

// TestCompareRespectsExcludeForBaseline verifies that a baseline entry
// matched by --exclude is out of the requested view, not "missing".
func TestCompareRespectsExcludeForBaseline(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Entries: mustScan(t, root, opts)}
	// The baseline contains skipme/secret.log; exclude it and delete it.
	if err := os.Remove(filepath.Join(root, "skipme", "secret.log")); err != nil {
		t.Fatal(err)
	}
	filtered := Options{Algo: model.AlgoSHA256, Exclude: []string{"skipme/**"}}
	results, err := Compare(root, base, filtered)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Path == "skipme/secret.log" {
			t.Fatalf("excluded baseline entry reported as %s", r.Kind)
		}
	}
	// Without the filter it must still be reported missing.
	results, err = Compare(root, base, opts)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range results {
		if r.Path == "skipme/secret.log" && r.Kind == model.KindMissing {
			found = true
		}
	}
	if !found {
		t.Fatal("missing report lost when no exclude is set")
	}
}

// TestCompareSingleFile verifies checking one file re-hashes only that
// file, matches it against its baseline entry, and does not flood the
// report with "missing" for the rest of the unscanned tree.
func TestCompareSingleFile(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Root: root, Entries: mustScan(t, root, opts)}
	// unchanged file
	res, err := Compare(filepath.Join(root, "a.log"), base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Path != "a.log" || res[0].Kind != model.KindUnmodified {
		t.Fatalf("clean single-file results = %+v, want one unmodified a.log", res)
	}
	// tampered file
	if err := os.WriteFile(filepath.Join(root, "a.log"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = Compare(filepath.Join(root, "a.log"), base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Kind != model.KindModified {
		t.Fatalf("tampered single-file results = %+v, want modified a.log", res)
	}
	// a file created after the baseline reports New, not an error
	added := filepath.Join(root, "added.log")
	if err := os.WriteFile(added, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = Compare(added, base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Kind != model.KindNew {
		t.Fatalf("new single-file compare = %+v, want new", res)
	}
}

// TestCompareSingleFileLegacyRoot covers baselines written by older
// versions of `init <file>`, which stored Root as the file itself and
// entries by base name. Check of that file must still resolve the
// entry (parent becomes the effective root) instead of reporting ".".
// TestCompareOutsideRootRejected verifies comparing a path that is not
// within the baseline's stored root fails with a clear error rather than
// producing a meaningless NEW/MISSING dump.
func TestCompareOutsideRootRejected(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Root: root, Entries: mustScan(t, root, opts)}
	other := t.TempDir()
	if _, err := Compare(other, base, opts); err == nil || !strings.Contains(err.Error(), "outside baseline root") {
		t.Fatalf("outside-root compare error = %v, want clear outside-root error", err)
	}
}

// TestCompareSubdirScopes verifies checking a subdirectory of the
// baseline root maps results onto baseline-relative paths (no
// contradictory NEW + MISSING for the same files).
func TestCompareSubdirScopes(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Root: root, Entries: mustScan(t, root, opts)}
	results, err := Compare(filepath.Join(root, "sub"), base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("subdir check returned %d results (%+v), want 2", len(results), results)
	}
	want := map[string]bool{"sub/c.log": false, "sub/deep/d.log": false}
	for _, r := range results {
		if _, ok := want[r.Path]; !ok {
			t.Fatalf("unexpected scoped result path %q in %+v", r.Path, results)
		}
		want[r.Path] = true
		if r.Kind != model.KindUnmodified {
			t.Errorf("scoped result %s = %s, want unmodified", r.Path, r.Kind)
		}
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("missing scoped result for %s", p)
		}
	}
}

// TestCompareDeletedSingleFileMissing verifies a deleted single-file
// target reports MISSING (not an error).
func TestCompareDeletedSingleFileMissing(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Root: root, Entries: mustScan(t, root, opts)}
	if err := os.Remove(filepath.Join(root, "a.log")); err != nil {
		t.Fatal(err)
	}
	results, err := Compare(filepath.Join(root, "a.log"), base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Path != "a.log" || results[0].Kind != model.KindMissing {
		t.Fatalf("deleted single-file results = %+v, want one MISSING a.log", results)
	}
}

// TestCompareLinkRetarget verifies a symlink whose target changed is
// reported as modified with a link-target reason.
func TestCompareLinkRetarget(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Root: root, Entries: mustScan(t, root, opts)}
	// Retarget link-to-a from a.log to b.log.
	if err := os.Remove(filepath.Join(root, "link-to-a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "b.log"), filepath.Join(root, "link-to-a")); err != nil {
		t.Fatal(err)
	}
	results, err := Compare(root, base, opts)
	if err != nil {
		t.Fatal(err)
	}
	var mod *model.Result
	for i := range results {
		if results[i].Path == "link-to-a" {
			mod = &results[i]
		}
	}
	if mod == nil || mod.Kind != model.KindModified {
		t.Fatalf("retargeted link results = %+v, want modified", results)
	}
	found := false
	for _, r := range mod.Reasons {
		if strings.HasPrefix(r, "link target") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected link-target reason, got %v", mod.Reasons)
	}
}

// TestCompareFileToDirSwap verifies a baselined file replaced by a
// directory is reported as a type change (modified), not MISSING.
func TestCompareFileToDirSwap(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Root: root, Entries: mustScan(t, root, opts)}
	if err := os.Remove(filepath.Join(root, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "notes.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "notes.txt", "inner.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := Compare(root, base, opts)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]model.Result{}
	for _, r := range results {
		byPath[r.Path] = r
	}
	r, ok := byPath["notes.txt"]
	if !ok {
		t.Fatalf("notes.txt missing from results: %v", byPath)
	}
	if r.Kind != model.KindModified {
		t.Fatalf("notes.txt (file->dir) = %s, want modified (type change)", r.Kind)
	}
	if r.Kind == model.KindMissing {
		t.Fatal("file->dir swap must not be reported as MISSING")
	}
}

func TestCompareSingleFileLegacyRoot(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	base := model.Baseline{Algorithm: opts.Algo, Root: filepath.Join(root, "a.log"), Entries: mustScan(t, root, opts)}
	res, err := Compare(filepath.Join(root, "a.log"), base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Path != "a.log" || res[0].Kind != model.KindUnmodified {
		t.Fatalf("legacy single-file results = %+v, want one unmodified a.log", res)
	}
}

// TestCompareDeletedSingleFileBaseline verifies that checking a path that
// was baselined as a single file and has since been deleted is reported
// MISSING (a finding), not a raw stat error (M3).
func TestCompareDeletedSingleFileBaseline(t *testing.T) {
	root := makeTree(t)
	opts := Options{Algo: model.AlgoSHA256}
	f := filepath.Join(root, "a.log")
	base := model.Baseline{
		Algorithm: opts.Algo,
		Root:      root,
		Entries:   []model.Entry{{Path: "a.log", Hash: "x", Algorithm: opts.Algo}},
	}
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	results, err := Compare(f, base, opts)
	if err != nil {
		t.Fatalf("deleted single file must not be a stat error: %v", err)
	}
	if len(results) != 1 || results[0].Path != "a.log" || results[0].Kind != model.KindMissing {
		t.Fatalf("deleted single file = %+v, want MISSING a.log", results)
	}
}

// TestIsWithinEmptyParent verifies an empty parent root contains every path.
func TestIsWithinEmptyParent(t *testing.T) {
	t.Parallel()
	if !isWithin("/any/absolute/path", "") {
		t.Fatal("empty parent should contain everything")
	}
}
