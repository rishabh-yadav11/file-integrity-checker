//go:build !unix

package hash

import "os"

// openNoFollow is best-effort on platforms without O_NOFOLLOW (e.g.
// Windows): it opens normally; callers fstat the descriptor and reject
// non-regular results, so a swapped symlink is still not hashed through.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
