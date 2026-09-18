//go:build !windows

package walk

import (
	"os"
	"syscall"
)

// ownership reads uid/gid from the stat info (POSIX platforms).
func ownership(info os.FileInfo) (uint32, uint32) {
	if st, ok := info.Sys().(*syscall.Stat_t); st != nil && ok {
		return st.Uid, st.Gid
	}
	return 0, 0
}
