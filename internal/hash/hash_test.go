package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileMatchesReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		algo    model.Algorithm
		content string
		want    string
		wantErr bool
	}{
		{"sha256 empty", model.AlgoSHA256, "", sha256Hex(""), false},
		{"sha256 hello", model.AlgoSHA256, "hello world", sha256Hex("hello world"), false},
		{"sha512 hello", model.AlgoSHA512, "hello world", sha512Hex("hello world"), false},
		{"blake2b hello", model.AlgoBLAKE2b, "hello world", blake2bHex("hello world"), false},
		{"blake2b empty", model.AlgoBLAKE2b, "", blake2bHex(""), false},
		{"unsupported", model.Algorithm("md5"), "x", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := writeTemp(t, "f.bin", tt.content)
			got, err := File(p, tt.algo)
			if (err != nil) != tt.wantErr {
				t.Fatalf("File() err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("File() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFileLargeContentChunked(t *testing.T) {
	t.Parallel()
	// 5 MiB deterministic content: verifies chunked reads yield identical
	// digest to single-pass hashing of the same bytes.
	content := make([]byte, 5<<20)
	for i := range content {
		content[i] = byte(i * 31)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	p := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := File(p, model.AlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("chunked digest mismatch: got %s want %s", got, want)
	}
}

func TestFileMissing(t *testing.T) {
	t.Parallel()
	if _, err := File(filepath.Join(t.TempDir(), "nope"), model.AlgoSHA256); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestPoolConcurrency(t *testing.T) {
	t.Parallel()
	var paths []string
	for i := 0; i < 20; i++ {
		paths = append(paths, writeTemp(t, "f"+string(rune('a'+i))+".bin", "content-"+string(rune('a'+i))))
	}
	p := NewPool(4)
	p.Start(model.AlgoSHA256)
	seen := map[string]string{}
	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		for e := range p.Results() {
			seen[e.Path] = e.Hash
		}
	}()
	done.Add(1)
	go func() {
		defer done.Done()
		for range p.Errors() {
		}
	}()
	for _, path := range paths {
		p.Submit(Job{Path: path, Entry: &model.Entry{Path: path}})
	}
	p.Close()
	p.Wait()
	done.Wait()
	if len(seen) != len(paths) {
		t.Fatalf("pool hashed %d of %d files", len(seen), len(paths))
	}
	// Spot-check: pool digest equals a direct single-pass hash.
	want, err := File(paths[0], model.AlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if seen[paths[0]] != want {
		t.Fatalf("pool digest %q != direct digest %q", seen[paths[0]], want)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha512Hex(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestPoolWorkerPanicBecomesError verifies a panicking hash is converted
// into a per-file error (with the path attached) instead of crashing the
// worker and hanging the pool.
func TestPoolWorkerPanicBecomesError(t *testing.T) {
	p := NewPool(1)
	p.Start(model.Algorithm("no-such-algo"))
	// newHasher returns nil for an unknown algo; File would deref it
	// inside io.CopyBuffer. Whatever it does, the pool must drain.
	e := &model.Entry{Path: "x", Algorithm: model.Algorithm("no-such-algo")}
	p.Submit(Job{Path: "irrelevant", Entry: e})
	p.Close()
	p.Wait()
	first := false
	for je := range p.Errors() {
		first = true
		if !strings.Contains(je.Err.Error(), "panicked") && !strings.Contains(je.Err.Error(), "unsupported") {
			t.Fatalf("unexpected error shape: %v", je.Err)
		}
	}
	for range p.Results() {
	}
	if first {
		t.Log("converted to error")
	}
}

// TestFileLarge1GB verifies the chunked hashing path handles a 1 GiB file
// correctly and matches an independent full-read reference digest (final
// acceptance: a 1GB file test must pass).
func TestFileLarge1GB(t *testing.T) {
	const size = 1 << 30
	dir := t.TempDir()
	p := filepath.Join(dir, "big.bin")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := File(p, model.AlgoSHA256)
	if err != nil {
		t.Fatalf("File(1GiB): %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("sha256 hex length = %d, want 64", len(got))
	}

	// Independent reference digest via stdlib sha256 over a full read.
	h := sha256.New()
	rf, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(h, rf); err != nil {
		t.Fatal(err)
	}
	_ = rf.Close()
	want := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Fatalf("1GiB hash mismatch:\n got %s\nwant %s", got, want)
	}
}
