//go:build !unix

package cmd

import "os"

// loosePerms reports whether a file is group/world readable. On platforms
// without meaningful POSIX permission bits (e.g. Windows, where Mode().Perm()
// is a constant 0666), the check is skipped entirely so keyfiles and
// baselines are not spuriously refused or warned about.
func loosePerms(fi os.FileInfo) bool {
	return false
}
