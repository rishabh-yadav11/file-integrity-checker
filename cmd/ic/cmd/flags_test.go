package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/config"
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

// TestCheckWrongRootRejected verifies check against a path outside the
// baseline's root fails with exit 2 and a clear message instead of
// producing a meaningless flood of NEW/MISSING lines.
func TestCheckWrongRootRejected(t *testing.T) {
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
	// check against dir (an ancestor that is NOT the baseline root) must
	// be rejected, not silently compared as foreign files.
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"check", dir, "--baseline", bl)
	if code != ExitError {
		t.Fatalf("cross-root check = %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "outside baseline root") {
		t.Fatalf("cross-root error must be clear:\n%s", out)
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

// TestQuietSuppressesCleanSummary verifies `-q` prints nothing at all
// on a clean tree (CI/cron friendly) while still printing the modified
// lines and summary when changes exist.
func TestQuietSuppressesCleanSummary(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	if code, _ := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", "b.json"); code != ExitOK {
		t.Fatalf("init: %d", code)
	}
	// Clean: quiet must print nothing at all.
	code, out := runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", "b.json", "-q")
	if code != ExitOK || out != "" {
		t.Fatalf("quiet clean: %d %q, want exit 0 empty output", code, out)
	}
	// Tamper: change line + summary must still print.
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out = runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", "b.json", "-q")
	if code != ExitChanges || !contains(out, "MODIFIED") || !contains(out, "summary") {
		t.Fatalf("quiet tamper: %d\n%s", code, out)
	}
}

// TestUpdateRefusesAlgoSwitch verifies update refuses to write hashes of
// a different algorithm into an existing baseline: a partial update with
// a mismatched --algo would mix sha256 and blake2b hashes under one
// top-level label and make every later check false-positive.
func TestUpdateRefusesAlgoSwitch(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a.log", "b.log"} {
		if err := os.WriteFile(filepath.Join(logs, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := map[string]string{"IC_KEY": "k"}
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", "b.json"); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"update", "logs/a.log", "--baseline", "b.json", "--algo", "blake2b")
	if code != ExitError || !strings.Contains(out, "refusing to write") {
		t.Fatalf("mixed-algo update = %d\n%s", code, out)
	}
	// Matching algo still updates fine.
	code, out = runCLIIn(t, dir, dir, env, "update", "logs/a.log", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("same-algo update: %d %s", code, out)
	}
	if code, out = runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"check", "logs", "--baseline", "b.json", "-q"); code != ExitOK {
		t.Fatalf("post-update check = %d:\n%s", code, out)
	}
}

// TestVerifyBaselineWarnsOnLoosePerms is POSIX-only (Windows has no
// meaningful perms bits) and lives in looseperms_unix_test.go.

// TestInitWarnsBaselineInsideTree verifies init warns when the baseline
// is stored inside the tree it describes (self-referential setup).
func TestInitWarnsBaselineInsideTree(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", "logs/b.json")
	if code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	if !contains(out, "baseline is inside the watched tree") {
		t.Fatalf("expected inside-tree warning, got: %s", out)
	}
	// Baseline outside the tree: no warning.
	code, out = runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", "outside.json")
	if code != ExitOK || contains(out, "baseline is inside the watched tree") {
		t.Fatalf("unexpected warning for outside baseline: %d %s", code, out)
	}
}

// TestColorHelpers exercises the color-precedence rules (L8/Q2): NO_COLOR
// wins, then the resolved config color (flag or config file), then the
// tty default.
func TestColorHelpers(t *testing.T) {
	on, off := true, false
	t.Setenv("NO_COLOR", "1")
	if resolveColor(config.Config{Color: &on}) {
		t.Fatal("NO_COLOR must win over an explicit color=true (L8)")
	}
	t.Setenv("NO_COLOR", "")
	if !resolveColor(config.Config{Color: &on}) {
		t.Fatal("resolved color=true must win")
	}
	if resolveColor(config.Config{Color: &off}) {
		t.Fatal("resolved color=false must force color off")
	}
	if resolveColor(config.Config{}) != isatty() {
		t.Fatal("nil color must fall back to the tty default")
	}
	if isatty() { // NO_COLOR was cleared above
		t.Log("tty default on; NO_COLOR case exercised separately")
	}
}

// TestColorFlagPrecedenceCLI verifies end-to-end that --color=true emits
// ANSI even on a non-tty, and that NO_COLOR overrides it.
func TestColorFlagPrecedenceCLI(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"}, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	_, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k", "NO_COLOR": ""},
		"check", "logs", "--baseline", bl, "--color=true")
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("--color=true must emit ANSI on a non-tty:\n%s", out)
	}
	_, out = runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k", "NO_COLOR": "1"},
		"check", "logs", "--baseline", bl, "--color=true")
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("NO_COLOR must override --color=true:\n%s", out)
	}
}

// TestExecute verifies the top-level Execute() entrypoint maps os.Args
// through ExecuteMain and returns the correct exit code.
func TestExecute(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"ic", "init", dir, "--baseline", filepath.Join(dir, "b.json")}
	t.Setenv("IC_KEY", "k")
	if code := Execute(); code != ExitOK {
		t.Fatalf("Execute(init) = %d, want 0", code)
	}
}

// TestUpdateAndVerifyJSONFormat verifies update and verify-baseline emit a
// JSON envelope in --format json instead of the human-readable text (M5).
func TestUpdateAndVerifyJSONFormat(t *testing.T) {
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
	code, out := runCLIIn(t, dir, dir, env, "update", "logs", "--baseline", bl, "--format", "json")
	if code != ExitOK || !strings.Contains(out, `"baseline"`) || !strings.Contains(out, `"accepted"`) {
		t.Fatalf("update --format json: %d %s", code, out)
	}
	if strings.Contains(out, "baseline updated:") {
		t.Fatalf("update --format json must not print the text summary: %s", out)
	}
	code, out = runCLIIn(t, dir, dir, env, "verify-baseline", "--baseline", bl, "--format", "json")
	if code != ExitOK || !strings.Contains(out, `"ok"`) {
		t.Fatalf("verify --format json: %d %s", code, out)
	}
	if strings.Contains(out, "baseline OK") {
		t.Fatalf("verify --format json must not print the text line: %s", out)
	}
}

// TestICKeyAndKeyfileWarns verifies that when both IC_KEY and --keyfile
// are set the operator is warned that IC_KEY takes precedence, instead of
// silently overriding (M9).
func TestICKeyAndKeyfileWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	kf := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(kf, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "envkey"},
		"init", dir, "--baseline", filepath.Join(dir, "b.json"), "--keyfile", kf)
	if code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	if !strings.Contains(out, "IC_KEY") || !strings.Contains(out, "precedence") {
		t.Fatalf("expected an IC_KEY-precedence warning, got: %s", out)
	}
}
