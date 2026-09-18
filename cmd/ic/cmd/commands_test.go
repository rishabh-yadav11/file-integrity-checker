package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullWorkflow(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}

	// init -> exit 0
	code, out := runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"init", logs, "--baseline", filepath.Join(dir, "baseline.json"))
	if code != ExitOK {
		t.Fatalf("init exit = %d, want 0 (out=%s)", code, out)
	}
	if !strings.Contains(out, "baseline written") {
		t.Fatalf("init output = %q", out)
	}

	// check clean -> exit 0
	code, out = runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"check", logs, "--baseline", filepath.Join(dir, "baseline.json"))
	if code != ExitOK {
		t.Fatalf("clean check exit = %d, want 0:\n%s", code, out)
	}

	// tamper -> exit 1
	if err := os.WriteFile(filepath.Join(logs, "one.log"), []byte("TAMPERED"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out = runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"check", logs, "--baseline", filepath.Join(dir, "baseline.json"))
	if code != ExitChanges {
		t.Fatalf("tampered check exit = %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "MODIFIED") || !strings.Contains(out, "one.log") {
		t.Fatalf("tamper not reported:\n%s", out)
	}

	// verify-baseline still OK (baseline itself untouched)
	code, out = runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"verify-baseline", "--baseline", filepath.Join(dir, "baseline.json"))
	if code != ExitOK || !strings.Contains(out, "baseline OK") {
		t.Fatalf("verify-baseline = %d %q", code, out)
	}

	// update accepts state
	code, out = runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"update", logs, "--baseline", filepath.Join(dir, "baseline.json"))
	if code != ExitOK || !strings.Contains(out, "baseline updated") {
		t.Fatalf("update = %d %q", code, out)
	}

	// check clean again -> exit 0
	code, out = runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"check", logs, "--baseline", filepath.Join(dir, "baseline.json"))
	if code != ExitOK {
		t.Fatalf("post-update check exit = %d, want 0:\n%s", code, out)
	}
}

func TestCheckTamperExitOne(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	f := filepath.Join(dir, "x.log")
	_ = os.WriteFile(f, []byte("v1"), 0o644)
	bl := filepath.Join(dir, "b.json")
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "kk"}, "init", dir, "--baseline", bl)
	if code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	_ = os.WriteFile(f, []byte("evil"), 0o644)
	code, _ = runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "kk"}, "check", dir, "--baseline", bl)
	if code != ExitChanges {
		t.Fatalf("tampered check exit = %d, want 1", code)
	}
}

func TestWrongKeyFailsCheck(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	f := filepath.Join(dir, "x.log")
	_ = os.WriteFile(f, []byte("x"), 0o644)
	bl := filepath.Join(dir, "b.json")
	code, _ := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "right"}, "init", dir, "--baseline", bl)
	if code != ExitOK {
		t.Fatalf("init failed: %d", code)
	}
	code, _ = runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "wrong"}, "verify-baseline", "--baseline", bl)
	if code != ExitError {
		t.Fatalf("wrong key verify exit = %d, want 2", code)
	}
}

func TestMissingKeyFails(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	t.Setenv("IC_KEY", "")
	code, out := runCLIIn(t, dir, dir, map[string]string{}, "init", dir, "--baseline", filepath.Join(dir, "b.json"))
	if code != ExitError {
		t.Fatalf("no-key init exit = %d, want 2 (out=%s)", code, out)
	}
}

func TestNoArgsShowsHelp(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	code, out := runCLIIn(t, t.TempDir(), t.TempDir(), map[string]string{})
	if code != ExitOK {
		t.Fatalf("bare root exit = %d, want 0:\n%s", code, out)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	code, _ := runCLIIn(t, t.TempDir(), t.TempDir(), map[string]string{"IC_KEY": "k"}, "bogus-command")
	if code != ExitError {
		t.Fatalf("unknown command exit = %d, want 2", code)
	}
}

func TestInitSingleFile(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	f := filepath.Join(dir, "solo.log")
	_ = os.WriteFile(f, []byte("data"), 0o644)
	bl := filepath.Join(dir, "b.json")
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"}, "init", f, "--baseline", bl)
	if code != ExitOK || !strings.Contains(out, "baseline written") {
		t.Fatalf("single-file init: %d %q", code, out)
	}
	// verify-baseline passes with baseline path flag
	code, out = runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"}, "verify-baseline", "--baseline", bl)
	if code != ExitOK {
		t.Fatalf("verify after single-file init: %d %s", code, out)
	}
}

// TestInitSingleFileBaselineRoundTrip verifies init/check/update on a
// single-file path produce a parent-rooted baseline with consistent
// paths (no "." or "../"-prefixed entries).
func TestInitSingleFileBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	code, out := runCLIIn(t, dir, dir, env, "init", "f.txt", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "b.json"))
	if strings.Contains(string(raw), `".."`) {
		t.Fatalf("baseline contains ../ entries: %s", raw)
	}
	code, out = runCLIIn(t, dir, dir, env, "check", "f.txt", "--baseline", "b.json")
	if code != ExitOK || !contains(out, "UNMODIFIED f.txt") {
		t.Fatalf("clean single-file check: %d %s", code, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out = runCLIIn(t, dir, dir, env, "check", "f.txt", "--baseline", "b.json")
	if code != ExitChanges || !contains(out, "MODIFIED f.txt") {
		t.Fatalf("tamper check: %d %s", code, out)
	}
	code, out = runCLIIn(t, dir, dir, env, "update", "f.txt", "--baseline", "b.json")
	if code != ExitOK || contains(out, "outside baseline root") {
		t.Fatalf("update single-file: %d %s", code, out)
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "b.json")); strings.Contains(string(raw), `"../`) {
		t.Fatalf("update wrote ../-prefixed entries: %s", raw)
	}
	code, out = runCLIIn(t, dir, dir, env, "check", "f.txt", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("post-update check: %d %s", code, out)
	}
}
