//go:build windows

package walk

import "os"

// ownership is a stub on Windows: uid/gid are not part of the POSIX
// stat record and the model uses 0. Windows SID tracking is out of
// scope; mode bits still cover the readable state.
func ownership(info os.FileInfo) (uint32, uint32) { return 0, 0 }
