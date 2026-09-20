// Package watch monitors paths in real time with fsnotify and alerts
// on tamper events, handling rotated logs safely.
package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	// webhook is the bounded async POSTer for alerts; it is wired up in
	// Run when WebhookURL is set, so direct emit test calls without Run
	// never block on webhooks.
	webhook *webhookDispatch
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

	// A bounded, ctx-cancelled POST dispatcher replaces a fresh goroutine
	// per event: a dead webhook can no longer wedge the watcher behind an
	// unbounded pile of goroutines, and queued events drain at shutdown.
	if cfg.WebhookURL != "" {
		cfg.webhook = newWebhookDispatch(cfg.WebhookURL, ctx)
		defer cfg.webhook.close() // drain in-flight/queued posts on exit
	}

	var (
		mu       sync.Mutex
		pending  = map[string]time.Time{}
		flushCh  = make(chan struct{}, 1)
		overflow int // fsnotify event-overflow count (M14)
	)
	// Baseline lookup index: handleEvent runs once per debounced event,
	// so index the baseline once up front instead of rebuilding an
	// O(entries) map (or linear scan) for every event burst.
	baseByPath := baseIndex(cfg.Baseline)
	// Debounce: coalesce bursts of fs events per path. A one-shot timer
	// is armed only while work is pending and stopped when the queue is
	// empty, instead of a 50ms ticker looping forever (L4).
	go func() {
		// processReady fires every path whose debounce window has elapsed
		// and returns the wait to the next deadline (0 = nothing pending).
		processReady := func() time.Duration {
			now := time.Now()
			mu.Lock()
			ready := make([]string, 0, len(pending))
			for p, t := range pending {
				if now.Sub(t) >= cfg.Debounce {
					ready = append(ready, p)
					delete(pending, p)
				}
			}
			var wait time.Duration
			for _, t := range pending {
				if w := cfg.Debounce - now.Sub(t); w > wait {
					wait = w
				}
			}
			mu.Unlock()
			for _, p := range ready {
				handleEvent(ctx, cfg, baseByPath, p)
			}
			return wait
		}
		for {
			wait := processReady()
			if wait <= 0 {
				// Nothing pending: block until a new event or shutdown.
				select {
				case <-ctx.Done():
					return
				case <-flushCh:
				}
				continue
			}
			// Something pending: sleep until its deadline or a newer
			// event (which may extend it), whichever comes first.
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-flushCh:
				timer.Stop()
			case <-timer.C:
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			cfg.Log.Info("watch stopped")
			return nil
		case err := <-watcher.Errors:
			handleWatcherError(cfg.Log, err, &overflow)
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Track newly created directories so their children are watched too.
			if ev.Op&fsnotify.Create != 0 {
				if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
					if err := watcher.Add(ev.Name); err != nil {
						cfg.Log.Warn("failed to watch new directory", slog.String("path", ev.Name), slog.String("err", err.Error()))
					}
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

// handleWatcherError logs an fsnotify watcher error. An event overflow
// means the kernel dropped events, so it is surfaced at Error level with
// a running count and a hint to run a full `check` (M14).
func handleWatcherError(log *slog.Logger, err error, overflow *int) {
	if errors.Is(err, fsnotify.ErrEventOverflow) {
		*overflow++
		log.Error("fsnotify event overflow: some changes were dropped",
			slog.Int("overflow_count", *overflow),
			slog.String("hint", "run 'check' for a full rescan"))
		return
	}
	log.Error("watcher error", slog.Any("err", err))
}

// watchRecursive adds the root and all subdirectories.
func watchRecursive(w *fsnotify.Watcher, root string, opts walk.Options) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err // unreadable directory: surface instead of ignoring
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err == nil && rel != "." && opts.ExcludedDir(filepath.ToSlash(rel)) {
			return filepath.SkipDir
		}
		return w.Add(p)
	})
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
	// process a single job, per debounced fs event). hash.File reuses the
	// shared chunkSize buffer (Q3).
	sum, err := hash.File(abs, opts.Algo)
	if err != nil {
		return nil, err
	}
	e.Hash = sum
	e.Algorithm = opts.Algo
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
	// Baseline-relative path: a watch root nested under the baseline root
	// (baseline on "wsub", watching "wsub/sub") must compare and emit
	// against the same keys `check` uses ("sub/file"), otherwise the
	// files the baseline originally recorded are misreported as NEW (M2).
	prefix := ""
	if cfg.Baseline.Root != "" {
		br, err1 := filepath.Abs(cfg.Baseline.Root)
		wr, err2 := filepath.Abs(cfg.Root)
		if err1 == nil && err2 == nil {
			if pr, err := filepath.Rel(br, wr); err == nil && pr != ".." && !strings.HasPrefix(pr, ".."+string(filepath.Separator)) {
				if s := filepath.ToSlash(pr); s != "." {
					prefix = s + "/"
				}
			}
		}
	}
	rel := filepath.ToSlash(mustRel(cfg.Root, path))
	if prefix != "" {
		rel = prefix + rel
	}
	// Respect the same include/exclude view as check: events on paths
	// the user filtered out must not produce alerts. (Dirs are already
	// pruned from the watcher; this covers file-level globs.)
	if cfg.ScanOpts.Skip(rel, false) {
		return
	}
	// Rotated logs: the old name vanished => report as missing only if
	// it was in the baseline; the new file is reported as new.
	if _, err := os.Lstat(path); err != nil {
		// Path vanished: report only if it was in the baseline.
		if e, ok := baseByPath[rel]; ok {
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
		entry, serr := walk.StatEntry(path, rel)
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
		if prefix != "" {
			e.Path = prefix + e.Path
		}
		old, ok := baseByPath[e.Path]
		switch {
		case !ok:
			emit(cfg, Event{Path: e.Path, Op: "create", Kind: model.KindNew, Time: time.Now()})
		default:
			if reasons := cfg.ScanOpts.Diff(e, old); len(reasons) > 0 {
				emit(cfg, Event{Path: e.Path, Op: "write", Kind: model.KindModified,
					Time: time.Now(), Details: strings.Join(reasons, ", ")})
			}
		}
	}
}

// trapMu guards trapSink: tests set it while emit reads it, so access is
// serialized to keep the race detector quiet even under concurrent runs
// (M15).
var trapMu sync.Mutex

// trapSink allows tests to capture events; nil in production.
var trapSink func(Event)

func getTrapSink() func(Event) {
	trapMu.Lock()
	defer trapMu.Unlock()
	return trapSink
}

func emit(cfg Config, ev Event) {
	if t := getTrapSink(); t != nil {
		t(ev)
	}
	if cfg.Out != nil {
		if b, err := json.Marshal(ev); err == nil {
			_, _ = cfg.Out.Write(append(b, '\n'))
		}
	}
	cfg.Log.Warn("tamper event", slog.String("path", ev.Path), slog.String("op", ev.Op), slog.String("kind", string(ev.Kind)))
	if cfg.webhook != nil {
		select {
		case cfg.webhook.ch <- ev:
		default:
			cfg.Log.Warn("webhook queue full; dropping event", slog.String("path", ev.Path))
		}
	}
}

// webhookClient bounds a single POST so a hung endpoint cannot block the
// dispatcher (and hence the watcher) indefinitely.
var webhookClient = &http.Client{Timeout: 10 * time.Second}

// postWebhook POSTs the event as JSON; errors are logged, never fatal.
func postWebhook(url string, ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient.Do(req)
	if err != nil {
		slog.Warn("webhook post failed", slog.String("err", err.Error()))
		return
	}
	_ = resp.Body.Close()
}

// webhookDispatch serializes webhook events through one worker and a
// bounded queue (queueLen), so a slow endpoint coalesces load instead of
// spawning one goroutine per event. It stops on the watch context or its
// own stop channel and, on shutdown, drains whatever is still queued
// before exiting so no alert is dropped by an abrupt teardown.
type webhookDispatch struct {
	url  string
	ch   chan Event
	stop chan struct{}
	wg   sync.WaitGroup
}

const webhookQueueLen = 64

func newWebhookDispatch(url string, ctx context.Context) *webhookDispatch {
	d := &webhookDispatch{url: url, ch: make(chan Event, webhookQueueLen), stop: make(chan struct{})}
	d.wg.Add(1)
	go d.run(ctx)
	return d
}

func (d *webhookDispatch) run(ctx context.Context) {
	defer d.wg.Done()
	for {
		select {
		case ev := <-d.ch:
			postWebhook(d.url, ev)
		case <-ctx.Done():
			d.drain()
			return
		case <-d.stop:
			d.drain()
			return
		}
	}
}

// drain posts anything still queued before the worker exits.
func (d *webhookDispatch) drain() {
	for {
		select {
		case ev := <-d.ch:
			postWebhook(d.url, ev)
		default:
			return
		}
	}
}

// close stops accepting work and waits for queued/in-flight posts to
// drain. Called exactly once via the Run teardown defer; it terminates
// the worker even when the watch context was never cancelled (e.g. the
// fsnotify event channel closed), so it never blocks forever.
func (d *webhookDispatch) close() {
	close(d.stop)
	d.wg.Wait()
}
