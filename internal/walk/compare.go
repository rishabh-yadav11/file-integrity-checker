package walk

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/hash"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// absRoot returns the absolute form of a scan/check root, tolerating
// errors by returning the input unchanged.
func absRoot(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

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
		baseRoot = absRoot(root)
	} else {
		baseRoot = absRoot(base.Root)
	}
	absChk := absRoot(root)

	info, err := os.Stat(root)
	if err != nil {
		// A deleted single-file target that is in the baseline is a
		// finding (MISSING, exit 1), not an error.
		if os.IsNotExist(err) {
			if r := deletedReport(root, base, baseRoot); r != nil {
				return []model.Result{*r}, nil
			}
			// A deleted root means every baselined entry vanished too:
			// report them all MISSING (a finding, exit 1) instead of
			// surfacing a raw stat error (M3).
			out := make([]model.Result, 0, len(base.Entries))
			for _, e := range base.Entries {
				out = append(out, model.Result{Path: e.Path, Kind: model.KindMissing})
			}
			return out, nil
		}
		return nil, err
	}
	var (
		current       []model.Entry
		singleFile    bool
		scope         string // non-empty when checking a subdir of the root
		unreadableErr *UnreadableError
		missingSkip   = map[string]bool{}
	)
	if !info.IsDir() {
		// Single-file check: re-hash just that file and compare it
		// against its baseline entry under the baseline's root. Only
		// the file itself is reported (no mass "missing" for the rest
		// of the tree, which was not scanned).
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		// Legacy single-file baselines stored Root as the file itself;
		// their entries are keyed by base name relative to the parent
		// directory, so treat the parent as the effective root.
		effRoot := baseRoot
		if base.Root != "" && absRoot(base.Root) == abs {
			effRoot = filepath.Dir(abs)
		}
		rel, err := filepath.Rel(effRoot, abs)
		if err != nil {
			return nil, err
		}
		if isOutside(rel) {
			return nil, fmt.Errorf("check: %s is outside baseline root %s (baseline was created for %s)", abs, baseRoot, base.Root)
		}
		e, err := StatEntry(abs, filepath.ToSlash(rel))
		if err != nil {
			return nil, err
		}
		// A symlink (or FIFO/socket/device) target is recorded, never
		// followed or opened: no content hash (a FIFO read would block).
		if fi, lerr := os.Lstat(abs); lerr == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
			current = []model.Entry{*e}
			singleFile = true
		} else {
			// One file: hash inline; a worker pool would start Workers
			// goroutines to process a single job. hash.File reuses the
			// shared chunkSize buffer (Q3).
			sum, err := hash.File(abs, opts.Algo)
			if err != nil {
				return nil, err
			}
			e.Hash = sum
			e.Algorithm = opts.Algo
			current = []model.Entry{*e}
			singleFile = true
		}
	} else {
		// Directory check must be within (or be) the baseline's root.
		// A different, non-overlapping path cannot be meaningfully
		// compared to this baseline.
		if !isWithin(absChk, baseRoot) {
			return nil, fmt.Errorf("check: %s is outside baseline root %s (baseline was created for %s)", absChk, baseRoot, base.Root)
		}
		var err error
		current, err = Scan(root, opts)
		if err != nil {
			if !errors.As(err, &unreadableErr) {
				return nil, err
			}
			// Unreadable files: still compare every readable sibling; the
			// UnreadableError is propagated at the end so the caller can
			// surface it (with an error exit code) without losing the
			// results that did come back.
		}
		// Map scan-relative paths onto baseRoot-relative paths so a
		// subdirectory check compares against the right baseline entries
		// ("sub/x" instead of a contradicting "x").
		if off, ok := offsetFrom(baseRoot, absChk); ok && off != "" {
			scope = off
			for i := range current {
				current[i].Path = off + "/" + current[i].Path
			}
		}
		// Unreadable files exist on disk but could not be verified; they
		// must never be reported as MISSING (they did not vanish).
		if unreadableErr != nil {
			for _, p := range unreadableErr.Paths {
				if scope != "" {
					p = scope + "/" + p
				}
				missingSkip[p] = true
			}
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
		if reasons := opts.Diff(cur, old); len(reasons) > 0 {
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
			// An unreadable file did not vanish; only it could not be
			// verified. Never report it as MISSING.
			if missingSkip[e.Path] {
				continue
			}
			// Respect the same include/exclude filters as the scan:
			// a baseline entry outside the requested view is out of
			// scope, not missing. (E.g. `check --exclude cache/**`
			// must not flag cached files as missing.)
			if opts.Skip(e.Path, false) {
				continue
			}
			// A scoped subdir check ignores baseline entries outside the
			// checked subtree rather than reporting them as missing.
			if scope != "" && !strings.HasPrefix(e.Path, scope+"/") {
				continue
			}
			// A baselined file that became a directory is a type change,
			// not a disappearance.
			if r := dirSwapResult(e, baseRoot); r != nil {
				out = append(out, *r)
				continue
			}
			out = append(out, model.Result{Path: e.Path, Kind: model.KindMissing})
		}
	}
	if unreadableErr != nil {
		return out, unreadableErr
	}
	return out, nil
}

// dirSwapResult returns a Modified result when a baseline entry that was
// a file now exists as a directory, or nil otherwise.
func dirSwapResult(e model.Entry, baseRoot string) *model.Result {
	full := filepath.Join(baseRoot, filepath.FromSlash(e.Path))
	if fi, err := os.Lstat(full); err == nil && fi.IsDir() {
		return &model.Result{Path: e.Path, Kind: model.KindModified,
			Reasons: []string{"type changed: file -> directory"}}
	}
	return nil
}

// isOutside reports whether a Rel result escapes its parent (e.g. "../x").
func isOutside(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// isWithin reports whether child is equal to or under parent.
func isWithin(child, parent string) bool {
	if parent == "" {
		return true
	}
	rel, err := filepath.Rel(absRoot(parent), absRoot(child))
	if err != nil {
		return false
	}
	return !isOutside(rel)
}

// offsetFrom returns, for a path strictly under parent, its slash-separated
// relative prefix ("" when equal), or ok=false when not under parent.
func offsetFrom(parent, child string) (string, bool) {
	rel, err := filepath.Rel(absRoot(parent), absRoot(child))
	if err != nil || isOutside(rel) {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return "", true
	}
	return rel, true
}

// deletedReport returns a MISSING result when a vanished path maps to a
// single-file baseline entry, else nil.
func deletedReport(root string, base model.Baseline, baseRoot string) *model.Result {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil
	}
	effRoot := baseRoot
	if base.Root != "" && absRoot(base.Root) == abs {
		effRoot = filepath.Dir(abs)
	}
	rel, err := filepath.Rel(effRoot, abs)
	if err != nil {
		return nil
	}
	relSlash := filepath.ToSlash(rel)
	for _, e := range base.Entries {
		if e.Path == relSlash {
			return &model.Result{Path: e.Path, Kind: model.KindMissing}
		}
	}
	return nil
}

// DiffEntries lists the metadata fields that differ between baseline and
// current (package-level; Options.Diff is the guard method that honors
// IgnoreMtime) (L14).
func DiffEntries(cur, old model.Entry) []string {
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
	if cur.LinkTarget != old.LinkTarget {
		reasons = append(reasons, fmt.Sprintf("link target %q -> %q", old.LinkTarget, cur.LinkTarget))
	}
	return reasons
}
