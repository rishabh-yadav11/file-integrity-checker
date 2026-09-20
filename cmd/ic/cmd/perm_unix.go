//go:build unix

package cmd

import "os"

// loosePerms reports whether a file is group/world readable. On POSIX the
// permission bits are meaningful, so 0644 (or any group/world bits) is
// flagged as loose.
func loosePerms(fi os.FileInfo) bool {
	return fi.Mode().Perm()&0o077 != 0
}
