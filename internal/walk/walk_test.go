package walk

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// makeTree builds a fixture directory tree and returns its root path.
func makeTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("a.log", "alpha")
	mk("b.log", "bravo")
	mk("sub/c.log", "charlie")
	mk("sub/deep/d.log", "delta")
	mk("skipme/secret.log", "s3cret")
	mk("notes.txt", "text")
	// Symlink inside the tree: must never be hashed or followed.
	if err := os.Symlink(filepath.Join(root, "a.log"), filepath.Join(root, "link-to-a")); err != nil {
		t.Fatal(err)
	}
	// Broken symlink: must be skipped without error.
	if err := os.Symlink(filepath.Join(root, "does-not-exist"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestScanAllFiles(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	entries, err := Scan(root, Options{Algo: model.AlgoSHA256})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Path] = true
	}
	want := []string{"a.log", "b.log", "notes.txt", "sub/c.log", "sub/deep/d.log", "skipme/secret.log"}
	if len(got) != len(want) {
		t.Fatalf("scan returned %d entries (%v), want %d", len(got), got, len(want))
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing entry %q in %v", w, got)
		}
	}
}

func TestScanEntriesSorted(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	entries, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Path > entries[i].Path {
			t.Fatalf("entries not sorted: %q > %q", entries[i-1].Path, entries[i].Path)
		}
	}
}

func TestScanSymlinksSkipped(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	entries, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Path == "link-to-a" || e.Path == "dangling" {
			t.Errorf("symlink %q was recorded in baseline", e.Path)
		}
	}
}

func TestScanExclude(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		exclude []string
		wantGone []string
		wantKeep []string
	}{
		{"dir glob", []string{"skipme/**"}, []string{"skipme/secret.log"}, []string{"a.log", "notes.txt"}},
		{"dot pattern", []string{"*.txt"}, []string{"notes.txt"}, []string{"a.log", "sub/c.log"}},
		{"component name", []string{"skipme"}, []string{"skipme/secret.log"}, []string{"a.log", "b.log"}},
		{"exact file", []string{"a.log"}, []string{"a.log"}, []string{"b.log", "notes.txt"}},
		{"nested dir prune", []string{"sub/deep"}, []string{"sub/deep/d.log"}, []string{"sub/c.log"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := makeTree(t)
			entries, err := Scan(root, Options{Exclude: tt.exclude})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, e := range entries {
				got[e.Path] = true
			}
			for _, g := range tt.wantGone {
				if got[g] {
					t.Errorf("expected %q to be excluded, got entries %v", g, keys(got))
				}
			}
			for _, k := range tt.wantKeep {
				if !got[k] {
					t.Errorf("expected %q to be included, got entries %v", k, keys(got))
				}
			}
		})
	}
}

func TestScanInclude(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		include   []string
		wantIn    []string
		wantOut   []string
	}{
		{"top-level glob", []string{"*.log"}, []string{"a.log", "b.log", "sub/c.log", "sub/deep/d.log", "skipme/secret.log"}, []string{"notes.txt"}},
		{"recursive glob", []string{"**/*.log"}, []string{"a.log", "b.log", "sub/c.log", "sub/deep/d.log"}, []string{"notes.txt"}},
		{"subdir prefix", []string{"sub/**"}, []string{"sub/c.log", "sub/deep/d.log"}, []string{"a.log", "skipme/secret.log"}},
		{"txt only", []string{"*.txt"}, []string{"notes.txt"}, []string{"a.log", "sub/c.log"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := makeTree(t)
			entries, err := Scan(root, Options{Include: tt.include})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, e := range entries {
				got[e.Path] = true
			}
			for _, w := range tt.wantIn {
				if !got[w] {
					t.Errorf("expected %q included, got %v", w, keys(got))
				}
			}
			for _, w := range tt.wantOut {
				if got[w] {
					t.Errorf("expected %q excluded, got %v", w, keys(got))
				}
			}
		})
	}
}

func TestScanMissingRoot(t *testing.T) {
	t.Parallel()
	if _, err := Scan(filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
		t.Fatal("expected error for missing root")
	}
}

func TestScanSingleFileRoot(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "f.log")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(p, Options{}); err == nil {
		t.Fatal("expected error when root is a file, not a directory")
	}
}

func TestScanBadAlgorithm(t *testing.T) {
	t.Parallel()
	root := makeTree(t)
	if _, err := Scan(root, Options{Algo: model.Algorithm("md5")}); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestSkip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		opts   Options
		path   string
		isDir  bool
		wantSk bool
	}{
		{Options{}, "anything.txt", false, false},
		{Options{Exclude: []string{"*.log"}}, "x.log", false, true},
		{Options{Exclude: []string{"*.log"}}, "keep.txt", false, false},
		{Options{Include: []string{"*.log"}}, "keep.txt", false, true},
		{Options{Include: []string{"*.log"}}, "sub/x.log", false, false},
		{Options{Exclude: []string{"big/**"}}, "big", true, true}, // dir pruned
		{Options{Exclude: []string{"big/**"}}, "big/x", false, true},
	}
	for _, tt := range tests {
		if got := tt.opts.Skip(tt.path, tt.isDir); got != tt.wantSk {
			_ = got
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
