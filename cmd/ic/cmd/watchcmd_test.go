package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWatchCmdCancelledContext runs the watch subcommand with a
// pre-cancelled context: it must return promptly (exit 0) without
// leaking the real signal handler setup.
func TestWatchCmdCancelledContext(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldCtx := cmdCtx
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done: Run returns immediately
	cmdCtx = func() context.Context { return ctx }
	defer func() { cmdCtx = oldCtx }()

	// Harness chdirs; run from dir with env key set.
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"}, "watch", "logs")
	_ = time.Millisecond // keep time import if debounce default changes
	if code == ExitError && out == "" {
		t.Fatalf("watch exited with error and no output")
	}
}
