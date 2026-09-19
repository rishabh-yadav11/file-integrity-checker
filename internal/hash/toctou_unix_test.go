//go:build unix

package hash

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// TestFileDoesNotFollowSymlink verifies hashing opens with O_NOFOLLOW and
// refuses to hash through a symlink, closing the Lstat-then-Open TOCTOU
// window (best-effort on non-unix platforms).
func TestFileDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := File(link, model.AlgoSHA256); err == nil {
		t.Fatal("expected error hashing a symlink (O_NOFOLLOW)")
	}
}
