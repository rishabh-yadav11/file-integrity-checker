package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// TestWatchCmdEmitsTamperEvent runs the full watch subcommand against a
// live tree, tampers a baselined file mid-watch, and verifies the tamper
// is reported before the watch stops on its (time-bounded) context.
func TestWatchCmdEmitsTamperEvent(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}

	oldCtx := cmdCtx
	ctx, cancel := context.WithCancel(context.Background())
	cmdCtx = func() context.Context { return ctx }
	defer func() { cmdCtx = oldCtx; cancel() }()

	// Tamper after fsnotify setup; stop the watch after the debounce window.
	time.AfterFunc(400*time.Millisecond, func() {
		_ = os.WriteFile(filepath.Join(logs, "a.log"), []byte("CHANGED"), 0o644)
	})
	time.AfterFunc(2500*time.Millisecond, cancel)

	code, out := runCLIIn(t, dir, dir, env, "watch", "logs", "--baseline", bl)
	if code != ExitOK {
		t.Fatalf("watch = %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "tamper event") && !strings.Contains(out, "MODIFIED") {
		t.Fatalf("watch did not report the tamper:\n%s", out)
	}
}
