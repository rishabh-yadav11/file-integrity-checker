//go:build !unix

package walk

import "os"

// ownership is a stub on platforms without POSIX stat uid/gid (Windows,
// plan9, ...): the model keeps 0/0 there.
//
// Note: a baseline created on a POSIX host records mode bits and uid/gid;
// checked on Windows (or vice versa) those metadata fields will not match
// and will be reported as differences. This is expected: move the whole
// baseline+key, not a cross-platform copy, when relocating (L13).
func ownership(info os.FileInfo) (uint32, uint32) { return 0, 0 }
