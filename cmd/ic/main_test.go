package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rishabh-yadav11/file-integrity-checker/cmd/ic/cmd"
)

// TestMainSmoke runs a full init/check/tamper cycle through the real
// ExecuteMain entrypoint, asserting the required exit codes.
func TestMainSmoke(t *testing.T) {
	t.Setenv("IC_KEY", "k")
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(logs, "a.log")
	if err := os.WriteFile(a, []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "b.json")

	if c := cmd.ExecuteMain([]string{"init", logs, "--baseline", bl}); c != cmd.ExitOK {
		t.Fatalf("init exit = %d, want %d", c, cmd.ExitOK)
	}
	if c := cmd.ExecuteMain([]string{"check", logs, "--baseline", bl}); c != cmd.ExitOK {
		t.Fatalf("clean check exit = %d, want %d", c, cmd.ExitOK)
	}
	if err := os.WriteFile(a, []byte("TAMPERED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := cmd.ExecuteMain([]string{"check", logs, "--baseline", bl}); c != cmd.ExitChanges {
		t.Fatalf("tampered check exit = %d, want %d", c, cmd.ExitChanges)
	}
}

// TestMainExitsCode exercises the real main() entrypoint by swapping
// exitFunc with a capture, so the os.Exit line is covered without dying
// (Q5).
func TestMainExitsCode(t *testing.T) {
	oldExit := exitFunc
	defer func() { exitFunc = oldExit }()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IC_KEY", "k")
	os.Args = []string{"ic", "init", logs, "--baseline", filepath.Join(dir, "b.json")}

	code := -1
	exitFunc = func(c int) { code = c }
	main()
	if code != cmd.ExitOK {
		t.Fatalf("main exit = %d, want %d", code, cmd.ExitOK)
	}
}
