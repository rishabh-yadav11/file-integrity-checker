package watch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/walk"
)

func TestExcludedDir(t *testing.T) {
	t.Parallel()
	tests := []struct {
		opts walk.Options
		rel  string
		want bool
	}{
		{walk.Options{Exclude: []string{"skipme/**"}}, "skipme", true},
		{walk.Options{Exclude: []string{"*.tmp"}}, "cache", false},
		{walk.Options{Exclude: []string{"skipme"}}, "deep/skipme", true},
		{walk.Options{}, "anything", false},
	}
	for i, tt := range tests {
		if got := excludedDir(tt.opts, tt.rel); got != tt.want {
			t.Errorf("case %d: excludedDir(%v) = %v, want %v", i, tt.rel, got, tt.want)
		}
	}
}

func TestScanSingle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "f.log")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := scanSingle(p, dir, walk.Options{Algo: model.AlgoSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "hello-should-be-relative" {
		// path is relative of root: file at root => its base name
		if entries[0].Path != filepath.Base(p) {
			t.Fatalf("entry path = %q, want base name", entries[0].Path)
		}
	}
	if entries[0].Hash == "" {
		t.Fatal("empty hash")
	}
}

func TestPostWebhook(t *testing.T) {
	t.Parallel()
	received := make(chan Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			t.Errorf("bad webhook body: %v", err)
			return
		}
		if ev.Path == "" {
			t.Error("webhook event missing path")
		}

		// drain channel to satisfy linter
		_ = received
		received <- ev
	}))
	defer srv.Close()
	postWebhook(srv.URL, Event{Path: "x.log", Op: "write", Kind: model.KindModified, Time: time.Now()})
	select {
	case ev := <-received:
		if ev.Path != "x.log" {
			t.Fatalf("webhook path = %q", ev.Path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook never called")
	}
	// Bad URL must not panic (fire-and-forget).
	postWebhook("http://127.0.0.1:1/nope", Event{Path: "y", Time: time.Now()})
}

func TestHandleEventMissingFile(t *testing.T) {
	root, base, _ := makeWatchFixture(t)
	trap := &eventTrap{ch: make(chan Event, 8)}
	setTrap(trap.trap)
	defer setTrap(nil)
	cfg := Config{
		Root:     root,
		ScanOpts: walk.Options{Algo: model.AlgoSHA256},
		Baseline: base,
		Debounce: 50 * time.Millisecond,
		Out:      nullWriter{},
		Log:      testLogger(),
	}
	// Direct call on vanished path: baseline has one.log; delete it first.
	if err := os.Remove(filepath.Join(root, "one.log")); err != nil {
		t.Fatal(err)
	}
	handleEvent(context.Background(), cfg, filepath.Join(root, "one.log"))
	select {
	case ev := <-trap.ch:
		if ev.Kind != model.KindMissing {
			t.Fatalf("kind = %v, want missing", ev.Kind)
		}
	default:
		t.Fatal("no event emitted for vanished file")
	}
}

func TestHandleEventNewFile(t *testing.T) {
	root, base, _ := makeWatchFixture(t)
	trap := &eventTrap{ch: make(chan Event, 8)}
	setTrap(trap.trap)
	defer setTrap(nil)
	cfg := Config{
		Root:     root,
		ScanOpts: walk.Options{Algo: model.AlgoSHA256},
		Baseline: base,
		Out:      nullWriter{},
		Log:      testLogger(),
	}
	// Directory event: must not panic (scanSingle on dir fails silently).
	handleEvent(context.Background(), cfg, filepath.Join(root, "sub"))
	// A genuinely new file under root: handleEvent hashes it and emits New.
	fresh := filepath.Join(root, "fresh.log")
	if err := os.WriteFile(fresh, []byte("fresh"), 0o644); err != nil {
		t.Fatal(err)
	}
	handleEvent(context.Background(), cfg, fresh)
	select {
	case ev := <-trap.ch:
		if ev.Path != "fresh.log" || ev.Kind != model.KindNew {
			t.Fatalf("event = %+v, want new fresh.log", ev)
		}
	default:
		t.Fatal("no New event emitted for fresh file")
	}
}

// TestEmitWritesToOut verifies emit serializes the event as a JSON line
// to the configured Out writer (previously Out was never written to).
func TestEmitWritesToOut(t *testing.T) {
	var buf strings.Builder
	cfg := Config{
		Out: &buf,
		Log: testLogger(),
	}
	emit(cfg, Event{Path: "a.log", Op: "write", Kind: model.KindModified, Time: time.Now()})
	line := buf.String()
	if !strings.Contains(line, `"a.log"`) || !strings.Contains(line, `"write"`) {
		t.Fatalf("Out = %q, want JSON line with path and op", line)
	}
	// Ensure it is a single line ending in newline.
	if !strings.HasSuffix(line, "\n") || strings.Count(strings.TrimSuffix(line, "\n"), "\n") != 0 {
		t.Fatalf("Out = %q, want exactly one JSON line", line)
	}
}

// TestHandleEventSymlinkSwap verifies that replacing a baselined regular
// file with a symlink is reported as a tamper (modified, op=symlink)
// instead of being hashed through the link target, and that a symlink
// with no baseline entry is reported as new.
func TestHandleEventSymlinkSwap(t *testing.T) {
	root, base, _ := makeWatchFixture(t)
	trap := &eventTrap{ch: make(chan Event, 8)}
	setTrap(trap.trap)
	defer setTrap(nil)
	cfg := Config{
		Root:     root,
		ScanOpts: walk.Options{Algo: model.AlgoSHA256},
		Baseline: base,
		Out:      nullWriter{},
		Log:      testLogger(),
	}
	// Replace a baselined file with a symlink to an outside target.
	target := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "one.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "one.log")); err != nil {
		t.Fatal(err)
	}
	handleEvent(context.Background(), cfg, filepath.Join(root, "one.log"))
	select {
	case ev := <-trap.ch:
		if ev.Kind != model.KindModified || ev.Op != "symlink" {
			t.Fatalf("event = %+v, want op=symlink kind=modified", ev)
		}
		if ev.Path != "one.log" {
			t.Fatalf("path = %q, want one.log", ev.Path)
		}
	default:
		t.Fatal("no event emitted for symlink swap")
	}
	// Brand-new symlink (not in baseline) must be New, not followed.
	link := filepath.Join(root, "freshlink")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	handleEvent(context.Background(), cfg, link)
	select {
	case ev := <-trap.ch:
		if ev.Kind != model.KindNew || ev.Op != "symlink" {
			t.Fatalf("event = %+v, want op=symlink kind=new", ev)
		}
		if ev.Path != "freshlink" {
			t.Fatalf("path = %q, want freshlink", ev.Path)
		}
	default:
		t.Fatal("no event emitted for fresh symlink")
	}
}

// TestHandleEventRespectsExclude verifies handleEvent stays silent for
// paths the user excluded (file-level globs; dirs are pruned earlier).
func TestHandleEventRespectsExclude(t *testing.T) {
	root, base, _ := makeWatchFixture(t)
	trap := &eventTrap{ch: make(chan Event, 8)}
	setTrap(trap.trap)
	defer setTrap(nil)
	cfg := Config{
		Root:     root,
		ScanOpts: walk.Options{Algo: model.AlgoSHA256, Exclude: []string{"two.log"}},
		Baseline: base,
		Out:      nullWriter{},
		Log:      testLogger(),
	}
	if err := os.WriteFile(filepath.Join(root, "two.log"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	handleEvent(context.Background(), cfg, filepath.Join(root, "two.log"))
	select {
	case ev := <-trap.ch:
		t.Fatalf("unexpected event for excluded path: %+v", ev)
	default:
	}
}
