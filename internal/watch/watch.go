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

	"github.com/rishabh-yadav11/file-integrity-checker/internal/baseline"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/hash"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/walk"
)

// Config for a watch session.
type Config struct {
	Root       string
	ScanOpts   walk.Options
	Baseline   model.Baseline
	Store      *baseline.Store
	BaselinePk string // baseline path for atomic refresh on --update-style consent
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
				handleEvent(ctx, cfg, p)
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
// It always drains the pool fully (results + errors + Wait) so a failing
// job can never leave the caller ranging an unclosed channel.
func scanSingle(abs, root string, opts walk.Options) ([]model.Entry, error) {
	e, err := walk.StatEntry(abs, filepath.ToSlash(mustRel(root, abs)))
	if err != nil {
		return nil, err
	}
	pool := hash.NewPool(opts.Workers)
	pool.Start(opts.Algo)
	pool.Submit(hash.Job{Path: abs, Entry: e})
	pool.Close()

	var (
		first   error
		entries []model.Entry
	)
	// Wait first: it closes both channels once workers finish, so the
	// range loops below are guaranteed to terminate.
	pool.Wait()
	for err := range pool.Errors() {
		if first == nil {
			first = err
		}
	}
	for res := range pool.Results() {
		entries = append(entries, *res)
	}
	if first != nil {
		return nil, first
	}
	return entries, nil
}

func mustRel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

// handleEvent re-hashes one path and reports any change vs baseline.
func handleEvent(ctx context.Context, cfg Config, path string) {
	if err := ctx.Err(); err != nil {
		return // shutting down: skip pending work
	}
	rel, err := filepath.Rel(cfg.Root, path)
	// Rotated logs: the old name vanished => report as missing only if
	// it was in the baseline; the new file is reported as new.
	if _, err := os.Lstat(path); err != nil {
		// Path vanished: find baseline entry.
		for _, e := range cfg.Baseline.Entries {
			if e.Path == filepath.ToSlash(rel) {
				emit(cfg, Event{Path: e.Path, Op: "remove", Kind: model.KindMissing,
					Time: time.Now(), Details: "file disappeared while watched"})
				break
			}
		}
		return
	}
	// Full-file hash of the changed path only (bounded work).
	cur, err := scanSingle(path, cfg.Root, cfg.ScanOpts)
	if err != nil {
		cfg.Log.Warn("rescan failed", slog.String("path", path), slog.String("err", err.Error()))
		return
	}
	baseByPath := map[string]model.Entry{}
	for _, e := range cfg.Baseline.Entries {
		baseByPath[e.Path] = e
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

// emit logs, traps (tests), and optionally webhooks an event.
func emit(cfg Config, ev Event) {
	if trapSink != nil {
		trapSink(ev)
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
