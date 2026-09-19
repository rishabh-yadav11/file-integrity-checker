//go:build unix

package hash

import (
	"os"
	"syscall"
)

// openNoFollow opens path without following a final symlink (O_NOFOLLOW),
// closing the Lstat-then-Open TOCTOU window on platforms that support it.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
