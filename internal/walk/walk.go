// Package walk recursively discovers regular files under a root,
// applying include/exclude globs, skipping symlinks and other
// non-regular entries, and hashing via a worker pool.
package walk

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/hash"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// Options configures a directory scan.
type Options struct {
	Algo    model.Algorithm
	Include []string // glob patterns (relative, slash-separated); empty = all
	Exclude []string // glob patterns to skip (checked on dir and file paths)
	Workers int      // hashing pool size; 0 = NumCPU
	// ExcludePaths lists absolute paths skipped verbatim during the
	// walk (no globbing). Used to keep a baseline stored inside the
	// tree it describes from flagging itself as new/modified.
	ExcludePaths []string
	// FollowSymlinks opts into hashing the targets of symlinks to
	// regular files. When false (default), symlinks are recorded as
	// entries carrying their target string but never followed.
	FollowSymlinks bool
	// Warn, when non-nil, is called for skipped non-regular files
	// (FIFOs, sockets, devices) so skips are visible instead of silent.
	Warn func(format string, args ...any)
}

// excludeAbs reports whether absolute path p matches any ExcludePaths
// entry (compared after cleaning).
func (o Options) excludeAbs(p string) bool {
	if len(o.ExcludePaths) == 0 {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	abs = filepath.Clean(abs)
	for _, e := range o.ExcludePaths {
		if filepath.Clean(e) == abs {
			return true
		}
	}
	return false
}

// excludedBy reports whether relPath matches any Exclude pattern.
func (o Options) excluded(relPath string, isDir bool) bool {
	clean := filepath.ToSlash(relPath)
	for _, pat := range o.Exclude {
		if matchGlob(pat, clean, isDir) {
			return true
		}
	}
	return false
}

// Skip reports whether relPath (slash-separated, relative to root) should
// be omitted: either it matches Exclude, or Include patterns exist and
// none match. Directories with Include set are only pruned when excluded;
// include filtering happens at file level so nested matches survive.
func (o Options) Skip(relPath string, isDir bool) bool {
	if o.excluded(relPath, isDir) {
		return true
	}
	if isDir || len(o.Include) == 0 {
		return false
	}
	clean := filepath.ToSlash(relPath)
	for _, pat := range o.Include {
		if ok, _ := doublestar.Match(pat, clean); ok {
			return false
		}
		// Pattern without slash matches any path component (like .gitignore).
		if !strings.Contains(pat, "/") {
			for _, seg := range strings.Split(clean, "/") {
				if ok, _ := doublestar.Match(pat, seg); ok {
					return false
				}
			}
		}
	}
	return true
}

// matchGlob matches pattern against path. For directories, a pattern
// ending in /** or a prefix pattern like "logs/*" also matches paths under it.
func matchGlob(pattern, path string, isDir bool) bool {
	if ok, _ := doublestar.Match(pattern, path); ok {
		return true
	}
	// Directory prefix: pattern "logs/**" should exclude "logs/x/y.log".
	if isDir && strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "**")
		if strings.HasPrefix(path+"/", prefix) {
			return true
		}
	}
	// Pattern without slash matches any path component (like .gitignore).
	if !strings.Contains(pattern, "/") {
		for _, seg := range strings.Split(path, "/") {
			if ok, _ := doublestar.Match(pattern, seg); ok {
				return true
			}
		}
	}
	return false
}

// Scan walks root, hashes every included regular file, and returns
// entries sorted by path. Symlinks are never followed: they are skipped
// (pointing into or out of the tree) so tampering via link swap is not
// silently traversed. Directories matching Exclude are pruned entirely.
func Scan(root string, opts Options) ([]model.Entry, error) {
	algo, err := model.ParseAlgorithm(string(opts.Algo))
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}

	pool := hash.NewPool(opts.Workers)
	pool.Start(algo)

	var (
		mu      sync.Mutex
		entries []*model.Entry
		errs    []error
	)
	collect := func(e *model.Entry) {
		mu.Lock()
		entries = append(entries, e)
		mu.Unlock()
	}
	var drainWG sync.WaitGroup
	drainWG.Add(1)
	go func() {
		defer drainWG.Done()
		for e := range pool.Results() {
			collect(e)
		}
	}()
	// Drain per-file hash errors (bounded channel) so a worker that hits
	// an unreadable file does not block, and its failure is surfaced to
	// the caller instead of silently dropping the file.
	var errWG sync.WaitGroup
	errWG.Add(1)
	go func() {
		defer errWG.Done()
		for e := range pool.Errors() {
			mu.Lock()
			errs = append(errs, e)
			mu.Unlock()
		}
	}()

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Report unreadable paths as errors but keep scanning siblings.
			errs = append(errs, fmt.Errorf("walk %s: %w", path, err))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		relSlash := filepath.ToSlash(rel)

		if d.IsDir() {
			if opts.excluded(relSlash, true) {
				return filepath.SkipDir
			}
			return nil // include patterns never prune directories
		}
		if d.Type()&os.ModeSymlink != 0 {
			// Symlinks are recorded as entries carrying their target
			// string (never followed by default). With FollowSymlinks,
			// a link to a regular file is hashed through its target.
			link, err := StatEntry(path, relSlash)
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			if opts.FollowSymlinks {
				if fi, statErr := os.Stat(path); statErr == nil && fi.Mode().IsRegular() {
					if opts.Skip(relSlash, false) {
						return nil
					}
					pool.Submit(hash.Job{Path: path, Entry: link})
					return nil
				}
			}
			if opts.Skip(relSlash, false) {
				return nil
			}
			collect(link)
			return nil
		}
		if !d.Type().IsRegular() {
			// FIFOs, sockets, devices: never open them (a FIFO would
			// block on read); skip with a visible warning.
			if opts.Warn != nil {
				opts.Warn("skipping non-regular entry %s (type %s)", path, d.Type())
			}
			return nil
		}
		if opts.Skip(relSlash, false) {
			return nil
		}
		if opts.excludeAbs(path) {
			return nil
		}
		entry, err := StatEntry(path, relSlash)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		pool.Submit(hash.Job{Path: path, Entry: entry})
		return nil
	})
	if walkErr != nil {
		pool.Close()
		pool.Wait()
		return nil, walkErr
	}

	pool.Close()
	pool.Wait()    // workers done; closes results and errors channels
	drainWG.Wait() // collector has seen every result
	errWG.Wait()   // per-file hash errors collected

	if len(errs) > 0 {
		return entriesToSlice(entries), errs[0]
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entriesToSlice(entries), nil
}

func entriesToSlice(es []*model.Entry) []model.Entry {
	out := make([]model.Entry, 0, len(es))
	for _, e := range es {
		out = append(out, *e)
	}
	return out
}

// StatEntry captures metadata for one file (hash filled later by pool).
// For a symlink it records the target string without following it.
func StatEntry(absPath, relPath string) (*model.Entry, error) {
	info, err := os.Lstat(absPath)
	if err != nil {
		return nil, err
	}
	uid, gid := ownership(info)
	target := ""
	if info.Mode()&os.ModeSymlink != 0 {
		if t, err := os.Readlink(absPath); err == nil {
			target = t
		}
	}
	return &model.Entry{
		Path:       relPath,
		Size:       info.Size(),
		Mode:       uint32(info.Mode().Perm()),
		UID:        uid,
		GID:        gid,
		Mtime:      info.ModTime(),
		LinkTarget: target,
	}, nil
}
