// Package watch monitors paths in real time with fsnotify and alerts
// on tamper events, handling rotated logs safely.
package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/fsnotify/fsnotify"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/hash"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/walk"
)

// Config for a watch session.
type Config struct {
	Root       string
	ScanOpts   walk.Options
	Baseline   model.Baseline
	WebhookURL string
	Debounce   time.Duration
	Out        interface{ Write([]byte) (int, error) }
	Log        *slog.Logger
}

// Event is a detected change during watching.
type Event struct {
	Path    string           `json:"path"`
	Op      string           `json:"op"`
	Kind    model.ChangeKind `json:"kind,omitempty"`
	Time    time.Time        `json:"time"`
	Details string           `json:"details,omitempty"`
}

// Run watches root until ctx is cancelled, reporting tamper events to
// out and optionally POSTing to webhookURL. Rotated logs (rename away
// and new file) produce NEW events rather than errors.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Debounce <= 0 {
		cfg.Debounce = 500 * time.Millisecond
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	// Root must exist: fail fast rather than silently watching nothing.
	if fi, err := os.Stat(cfg.Root); err != nil {
		return fmt.Errorf("watch: stat %s: %w", cfg.Root, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("watch: %s is not a directory", cfg.Root)
	}

	// Watch the root recursively (dirs only, skip excluded).
	if err := watchRecursive(watcher, cfg.Root, cfg.ScanOpts); err != nil {
		return err
	}
	cfg.Log.Info("watching", "root", cfg.Root, "debounce", cfg.Debounce.String())

	var (
		mu      sync.Mutex
		pending = map[string]time.Time{}
		flushCh = make(chan struct{}, 1)
	)
	// Baseline lookup index: handleEvent runs once per debounced event,
	// so index the baseline once up front instead of rebuilding an
	// O(entries) map (or linear scan) for every event burst.
	baseByPath := baseIndex(cfg.Baseline)
	// Debounce: coalesce bursts of fs events per path.
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-flushCh:
			case <-ticker.C:
			}
			mu.Lock()
			ready := make([]string, 0, len(pending))
			for p, t := range pending {
				if time.Since(t) >= cfg.Debounce {
					ready = append(ready, p)
					delete(pending, p)
				}
			}
			mu.Unlock()
			for _, p := range ready {
				handleEvent(ctx, cfg, baseByPath, p)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			cfg.Log.Info("watch stopped")
			return nil
		case err := <-watcher.Errors:
			cfg.Log.Error("watcher error", slog.Any("err", err))
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Track newly created directories so their children are watched too.
			if ev.Op&fsnotify.Create != 0 {
				if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
					_ = watcher.Add(ev.Name)
				}
			}
			// Handle rename/remove as events on the old path.
			mu.Lock()
			pending[ev.Name] = time.Now()
			mu.Unlock()
			select {
			case flushCh <- struct{}{}:
			default:
			}
		}
	}
}

// watchRecursive adds the root and all subdirectories.
func watchRecursive(w *fsnotify.Watcher, root string, opts walk.Options) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: skip
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err == nil && rel != "." && opts.Exclude != nil && excludedDir(opts, filepath.ToSlash(rel)) {
			return filepath.SkipDir
		}
		return w.Add(p)
	})
}

// excludedDir reports whether a directory path is covered by exclude globs
// (mirrors walk's pruning rules without importing unexported helpers).
func excludedDir(opts walk.Options, rel string) bool {
	for _, pat := range opts.Exclude {
		if ok, _ := doublestar.Match(pat, rel); ok {
			return true
		}
		if !strings.Contains(pat, "/") {
			for _, seg := range strings.Split(rel, "/") {
				if ok, _ := doublestar.Match(pat, seg); ok {
					return true
				}
			}
		}
	}
	return false
}

// scanSingle hashes one file relative to root (helper for handleEvent).
// Hashing is inlined: one file does not need a worker pool, and this
// runs on every debounced fs event.
func scanSingle(abs, root string, opts walk.Options) ([]model.Entry, error) {
	e, err := walk.StatEntry(abs, filepath.ToSlash(mustRel(root, abs)))
	if err != nil {
		return nil, err
	}
	// One file: hash inline instead of spinning up a full worker pool
	// (the pool would launch Workers goroutines and three channels to
	// process a single job, per debounced fs event).
	sum, err := hash.FileBuffer(abs, opts.Algo, make([]byte, 1<<20))
	if err != nil {
		return nil, err
	}
	e.Hash = sum
	return []model.Entry{*e}, nil
}

// baseIndex maps baseline entries by slash-separated relative path so
// event handling does O(1) lookups instead of linear scans.
func baseIndex(b model.Baseline) map[string]model.Entry {
	m := make(map[string]model.Entry, len(b.Entries))
	for _, e := range b.Entries {
		m[e.Path] = e
	}
	return m
}

func mustRel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

// handleEvent re-hashes one path and reports any change vs baseline.
// baseByPath is the prebuilt baseline index (built once in Run).
func handleEvent(ctx context.Context, cfg Config, baseByPath map[string]model.Entry, path string) {
	if err := ctx.Err(); err != nil {
		return // shutting down: skip pending work
	}
	rel, _ := filepath.Rel(cfg.Root, path)
	// Respect the same include/exclude view as check: events on paths
	// the user filtered out must not produce alerts. (Dirs are already
	// pruned from the watcher; this covers file-level globs.)
	if cfg.ScanOpts.Skip(filepath.ToSlash(rel), false) {
		return
	}
	// Rotated logs: the old name vanished => report as missing only if
	// it was in the baseline; the new file is reported as new.
	if _, err := os.Lstat(path); err != nil {
		// Path vanished: report only if it was in the baseline.
		if e, ok := baseByPath[filepath.ToSlash(rel)]; ok {
			emit(cfg, Event{Path: e.Path, Op: "remove", Kind: model.KindMissing,
				Time: time.Now(), Details: "file disappeared while watched"})
		}
		return
	}
	// Symlink swap: hashing through the link would silently hash the
	// target file and report a mere content change. Baselines never
	// contain symlinks (walk skips them), so treat this as a tamper of
	// the original entry instead of following the link.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		// Record the link (never follow); compare against any baseline
		// entry to distinguish a retarget, a file->link swap, or a new link.
		entry, serr := walk.StatEntry(path, filepath.ToSlash(rel))
		if serr != nil {
			cfg.Log.Warn("rescan failed", slog.String("path", path), slog.String("err", serr.Error()))
			return
		}
		old, ok := baseByPath[entry.Path]
		switch {
		case !ok:
			emit(cfg, Event{Path: entry.Path, Op: "symlink", Kind: model.KindNew,
				Time: time.Now(), Details: "symlink created under watched root"})
		case old.LinkTarget == "":
			emit(cfg, Event{Path: entry.Path, Op: "symlink", Kind: model.KindModified,
				Time: time.Now(), Details: "path changed from regular file to symlink"})
		case old.LinkTarget != entry.LinkTarget:
			emit(cfg, Event{Path: entry.Path, Op: "symlink", Kind: model.KindModified,
				Time: time.Now(), Details: "symlink retargeted"})
		}
		return
	}
	// Full-file hash of the changed path only (bounded work).
	cur, err := scanSingle(path, cfg.Root, cfg.ScanOpts)
	if err != nil {
		cfg.Log.Warn("rescan failed", slog.String("path", path), slog.String("err", err.Error()))
		return
	}
	for _, e := range cur {
		old, ok := baseByPath[e.Path]
		switch {
		case !ok:
			emit(cfg, Event{Path: e.Path, Op: "create", Kind: model.KindNew, Time: time.Now()})
		default:
			if reasons := walk.Diff(e, old); len(reasons) > 0 {
				emit(cfg, Event{Path: e.Path, Op: "write", Kind: model.KindModified,
					Time: time.Now(), Details: strings.Join(reasons, ", ")})
			}
		}
	}
}

// trapSink allows tests to capture events; nil in production.
var trapSink func(Event)

// emit logs, traps (tests), and optionally webhooks an event. The event
// is also serialized as one JSON line to Out when Out is a non-nil
// writer distinct from the default.
func emit(cfg Config, ev Event) {
	if trapSink != nil {
		trapSink(ev)
	}
	if cfg.Out != nil {
		if b, err := json.Marshal(ev); err == nil {
			_, _ = cfg.Out.Write(append(b, '\n'))
		}
	}
	cfg.Log.Warn("tamper event", slog.String("path", ev.Path), slog.String("op", ev.Op), slog.String("kind", string(ev.Kind)))
	if cfg.WebhookURL != "" {
		go postWebhook(cfg.WebhookURL, ev)
	}
}

// postWebhook POSTs the event as JSON; errors are logged, never fatal.
func postWebhook(url string, ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("webhook post failed", slog.String("err", err.Error()))
		return
	}
	_ = resp.Body.Close()
}
