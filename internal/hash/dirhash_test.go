package hash

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// Regression: hashing a directory path previously deadlocked the worker
// pool (io.CopyBuffer on a directory fd blocks forever on Linux).
// File must reject directories with an error instead.
func TestFileDirectoryRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := File(sub, model.AlgoSHA256); err == nil {
		t.Fatal("expected error hashing a directory, got nil (would deadlock)")
	}
	// Through the pool too: must terminate, no hang.
	pool := NewPool(1)
	pool.Start(model.AlgoSHA256)
	pool.Submit(Job{Path: sub, Entry: &model.Entry{Path: "sub"}})
	pool.Close()
	pool.Wait() // workers done; closes results and errors channels
	for range pool.Results() {
	}
	for range pool.Errors() {
	}
}
