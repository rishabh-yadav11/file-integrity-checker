package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFlagCompletionsAndFormats exercises --algo validation, --format json,
// and flag parsing paths not hit by the main workflow tests.
func TestFormatJSONAndAlgoFlags(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "b.json")

	code, out := runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"init", logs, "--baseline", bl, "--algo", "sha512")
	if code != ExitOK || !contains(out, "sha512") {
		t.Fatalf("init sha512: %d %q", code, out)
	}
	_ = os.WriteFile(filepath.Join(logs, "one.log"), []byte("nope"), 0o644)
	code, out = runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"check", logs, "--baseline", bl, "--format", "json", "--algo", "sha512")
	if code != ExitChanges || !contains(out, `"kind"`) {
		t.Fatalf("json check: %d %q", code, out)
	}
}

// contains is strings.Contains with a short name for compact asserts.
func contains(s, sub string) bool { return strings.Contains(s, sub) }

// TestKeyfileFlag covers resolveKey's --keyfile branch.
func TestKeyfileFlag(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.log")
	_ = os.WriteFile(f, []byte("x"), 0o644)
	kf := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(kf, []byte("filekey"), 0o600); err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "b.json")
	code, out := runCLIIn(t, dir, dir, map[string]string{},
		"init", dir, "--baseline", bl, "--keyfile", kf)
	if code != ExitOK || !contains(out, "baseline written") {
		t.Fatalf("keyfile init: %d %q", code, out)
	}
	// verify with same keyfile
	code, _ = runCLIIn(t, dir, dir, map[string]string{},
		"verify-baseline", "--baseline", bl, "--keyfile", kf)
	if code != ExitOK {
		t.Fatalf("keyfile verify: %d", code)
	}
	// wrong keyfile must fail
	bad := filepath.Join(dir, "bad.bin")
	_ = os.WriteFile(bad, []byte("nope"), 0o600)
	code, _ = runCLIIn(t, dir, dir, map[string]string{},
		"verify-baseline", "--baseline", bl, "--keyfile", bad)
	if code != ExitError {
		t.Fatalf("wrong keyfile verify = %d, want 2", code)
	}
}
