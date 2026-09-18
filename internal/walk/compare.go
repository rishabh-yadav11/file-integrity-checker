package walk

import (
	"crypto/hmac"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/hash"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// Compare hashes the current state of root (via Scan, or a single file)
// and diffs it against the baseline. Returns results for every relevant
// file: Unmodified, Modified (with reasons), New, Missing. A single-file
// root re-hashes just that file and only reports on it.
func Compare(root string, base model.Baseline, opts Options) ([]model.Result, error) {
	if base.Algorithm != opts.Algo {
		return nil, fmt.Errorf("baseline algorithm %q does not match requested %q", base.Algorithm, opts.Algo)
	}
	baseRoot := base.Root
	if baseRoot == "" {
		baseRoot = root
	}
	var (
		current    []model.Entry
		singleFile bool
	)
	if info, err := os.Stat(root); err != nil {
		return nil, err
	} else if !info.IsDir() {
		// Single-file check: re-hash just that file and compare it
		// against its baseline entry under the baseline's root. Only
		// the file itself is reported (no mass "missing" for the rest
		// of the tree, which was not scanned).
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(baseRoot, abs)
		if err != nil {
			return nil, err
		}
		e, err := StatEntry(abs, filepath.ToSlash(rel))
		if err != nil {
			return nil, err
		}
		pool := hash.NewPool(opts.Workers)
		pool.Start(opts.Algo)
		pool.Submit(hash.Job{Path: abs, Entry: e})
		pool.Close()
		pool.Wait()
		var firstErr error
		for err := range pool.Errors() {
			if firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return nil, firstErr
		}
		for res := range pool.Results() {
			current = append(current, *res)
		}
		singleFile = true
	} else {
		var err error
		current, err = Scan(root, opts)
		if err != nil {
			return nil, err
		}
	}
	currentByPath := make(map[string]model.Entry, len(current))
	for _, e := range current {
		currentByPath[e.Path] = e
	}
	baseByPath := make(map[string]model.Entry, len(base.Entries))
	for _, e := range base.Entries {
		baseByPath[e.Path] = e
	}

	out := make([]model.Result, 0, len(current)+len(base.Entries))
	for _, cur := range current {
		old, ok := baseByPath[cur.Path]
		if !ok {
			out = append(out, model.Result{Path: cur.Path, Kind: model.KindNew})
			continue
		}
		if reasons := Diff(cur, old); len(reasons) > 0 {
			out = append(out, model.Result{Path: cur.Path, Kind: model.KindModified, Reasons: reasons})
		} else {
			out = append(out, model.Result{Path: cur.Path, Kind: model.KindUnmodified})
		}
	}
	if singleFile {
		// Scoped view: only the requested file's state is relevant.
		return out, nil
	}
	for _, e := range base.Entries {
		if _, ok := currentByPath[e.Path]; !ok {
			// Respect the same include/exclude filters as the scan:
			// a baseline entry outside the requested view is out of
			// scope, not missing. (E.g. `check --exclude cache/**`
			// must not flag cached files as missing.)
			if opts.Skip(e.Path, false) {
				continue
			}
			out = append(out, model.Result{Path: e.Path, Kind: model.KindMissing})
		}
	}
	return out, nil
}

// Diff lists the metadata fields that differ between baseline and current.
func Diff(cur, old model.Entry) []string {
	var reasons []string
	if !hmac.Equal([]byte(cur.Hash), []byte(old.Hash)) {
		reasons = append(reasons, "hash")
	}
	if cur.Size != old.Size {
		reasons = append(reasons, fmt.Sprintf("size %d -> %d", old.Size, cur.Size))
	}
	if cur.Mode != old.Mode {
		reasons = append(reasons, fmt.Sprintf("mode %o -> %o", old.Mode, cur.Mode))
	}
	if cur.UID != old.UID {
		reasons = append(reasons, fmt.Sprintf("uid %d -> %d", old.UID, cur.UID))
	}
	if cur.GID != old.GID {
		reasons = append(reasons, fmt.Sprintf("gid %d -> %d", old.GID, cur.GID))
	}
	if !cur.Mtime.Equal(old.Mtime) {
		reasons = append(reasons, "mtime")
	}
	return reasons
}
