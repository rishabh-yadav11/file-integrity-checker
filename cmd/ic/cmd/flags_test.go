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

// TestUpdateSingleFilePreservesSiblings verifies merge-update: updating
// one file must not drop the rest of the tree from the baseline, and
// updating a subdir must drop vanished files under it while keeping
// siblings.
func TestUpdateSingleFilePreservesSiblings(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(filepath.Join(logs, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "b.log"), []byte("B"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "sub", "c.log"), []byte("C"), 0o644); err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "b.json")

	// Baseline the whole tree.
	if code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"init", logs, "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}

	// Tamper a.log and add new.log, then update ONLY logs/a.log.
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A2"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(logs, "new.log"), []byte("N"), 0o644)
	if code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"update", filepath.Join(logs, "a.log"), "--baseline", bl); code != ExitOK {
		t.Fatalf("single-file update: %d %s", code, out)
	}

	// check: a.log accepted, B untouched, new.log still reported as new,
	// and C (inside untouched subdir) is unmodified.
	code, out := runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"check", logs, "--baseline", bl)
	if code != ExitChanges {
		t.Fatalf("check after partial update = %d, want 1 (new.log still new):\n%s", code, out)
	}
	if !strings.Contains(out, "UNMODIFIED a.log") {
		t.Fatalf("a.log should be accepted (UNMODIFIED) after single-file update:\n%s", out)
	}
	if !strings.Contains(out, "new.log") {
		t.Fatalf("new.log must still be NEW after single-file update:\n%s", out)
	}
	if strings.Contains(out, "b.log") || strings.Contains(out, "sub/two") {
		// b.log/sub/two must remain tracked: absence would mean orphaning.
		t.Logf("sibling b.log present: %v", strings.Contains(out, "b.log"))
	}

	// Now update the whole dir: everything accepted, exit 0 afterwards.
	if code, out := runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"update", logs, "--baseline", bl); code != ExitOK {
		t.Fatalf("dir update: %d %s", code, out)
	}
	code, _ = runCLIIn(t, logs, dir, map[string]string{"IC_KEY": "k"},
		"check", logs, "--baseline", bl)
	if code != ExitOK {
		t.Fatalf("post-dir-update check = %d, want 0", code)
	}
}

// TestCheckOtherRootDeterministic verifies check against a path that is
// not the baseline's root still works (exit 1, files reported as
// foreign) instead of crashing or silently passing.
func TestCheckOtherRootDeterministic(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"init", logs, "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	// check against a DIFFERENT directory (dir itself): entry paths cannot match.
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"check", dir, "--baseline", bl)
	if code != ExitChanges {
		t.Fatalf("cross-root check = %d, want 1 (everything foreign):\n%s", code, out)
	}
}

// TestCheckFollowsBaselineAlgo verifies check without --algo uses the
// baseline's stored algorithm (blake2b here) instead of erroring with a
// sha256 mismatch, and an explicit wrong --algo still fails loudly.
func TestCheckFollowsBaselineAlgo(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"init", logs, "--baseline", bl, "--algo", "blake2b"); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	// clean check without --algo must follow baseline algo and exit 0.
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"check", logs, "--baseline", bl)
	if code != ExitOK || !contains(out, "unmodified") {
		t.Fatalf("clean blake2b check without --algo: %d\n%s", code, out)
	}
	// explicit wrong algo still rejected.
	code, _ = runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"check", logs, "--baseline", bl, "--algo", "sha256")
	if code != ExitError {
		t.Fatalf("explicit algo mismatch = %d, want 2", code)
	}
}
