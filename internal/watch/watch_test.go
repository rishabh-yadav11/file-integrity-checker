package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/walk"
)

// eventTrap captures emitted events for assertions.
type eventTrap struct {
	ch chan Event
}

func (t *eventTrap) trap(ev Event) {
	select {
	case t.ch <- ev:
	default:
	}
}

// makeWatchFixture creates a watched tree with a baseline.
func makeWatchFixture(t *testing.T) (string, model.Baseline, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one.log"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "two.log"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := walk.Scan(root, walk.Options{Algo: model.AlgoSHA256})
	if err != nil {
		t.Fatal(err)
	}
	return root, model.Baseline{
		Version:   model.BaselineVersion,
		Algorithm: model.AlgoSHA256,
		CreatedAt: time.Now(),
		Root:      root,
		Entries:   entries,
	}, nil
}

func TestRunDetectsTamper(t *testing.T) {
	t.Parallel()
	root, base, _ := makeWatchFixture(t)
	trap := &eventTrap{ch: make(chan Event, 16)}
	cfg := Config{
		Root:     root,
		ScanOpts: walk.Options{Algo: model.AlgoSHA256},
		Baseline: base,
		Debounce: 100 * time.Millisecond,
		Out:      nullWriter{},
		Log:      testLogger(),
	}
	// Install trap into package-level emit channel.
	setTrap(trap.trap)
	defer setTrap(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, cfg) }()

	// Tamper after watcher startup.
	time.Sleep(300 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(root, "one.log"), []byte("TAMPERED"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-trap.ch:
		if ev.Path != "one.log" {
			t.Fatalf("event path = %q, want one.log", ev.Path)
		}
		if ev.Kind != model.KindModified && ev.Kind != model.KindNew {
			t.Fatalf("event kind = %q", ev.Kind)
		}
	case err := <-runErr:
		t.Fatalf("watch ended early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tamper event")
	}
}

func TestRunMissingRoot(t *testing.T) {
	t.Parallel()
	cfg := Config{Root: filepath.Join(t.TempDir(), "gone"), Debounce: 50 * time.Millisecond}
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("expected error for missing root")
	}
}

// setTrap installs/removes the emit trap.
func setTrap(f func(Event)) { trapSink = f }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&sinkWriter{}, nil))
}

type sinkWriter struct{}

func (s *sinkWriter) Write(p []byte) (int, error) { return len(p), nil }

type nullWriter struct{}

func (nullWriter) Write(p []byte) (int, error) { return len(p), nil }
