package watch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
