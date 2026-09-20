package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestBaselineInsideTreeSelfExcluded verifies that a baseline stored
// inside the tree it describes is auto-excluded from scans, so
// `init .` then `check .` exit 0 instead of flagging the baseline as NEW.
func TestBaselineInsideTreeSelfExcluded(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
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
		t.Fatalf("expected self-referential warning, got: %s", out)
	}
	code, out = runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", "logs/b.json")
	if code != ExitOK {
		t.Fatalf("check after in-tree init = %d, want 0 (baseline must not flag itself):\n%s", code, out)
	}
}

// TestUnreadableFileExitsError verifies that a file which cannot be read
// (e.g. permission denied) fails init and check with exit 2 and an error
// that names the file, rather than silently dropping it at init or
// misreporting it as MISSING at check.
func TestUnreadableFileExitsError(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(logs, "secret.log")
	if err := os.WriteFile(secret, []byte("S"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	bl := filepath.Join(dir, "b.json")

	// Baseline while everything is readable, then lock one file down.
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("baseline init: %d %s", code, out)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(secret); err == nil {
		f.Close()
		t.Skip("running as root; permission checks are ineffective")
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o600) })

	// check must exit 2 and name the file, not report MISSING.
	code, out := runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl)
	if code != ExitError {
		t.Fatalf("check with unreadable file = %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "secret.log") {
		t.Fatalf("check error must name the file:\n%s", out)
	}
	if strings.Contains(out, "MISSING") {
		t.Fatalf("unreadable file must not be reported as MISSING:\n%s", out)
	}
}

// TestUpdatePrunesDeletedFiles verifies `rm f; update; check` is clean:
// a full-directory update must drop entries for files that no longer
// exist instead of leaving them reported as MISSING forever.
func TestUpdatePrunesDeletedFiles(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "b.log"), []byte("B"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	if err := os.Remove(filepath.Join(logs, "b.log")); err != nil {
		t.Fatal(err)
	}
	if code, out := runCLIIn(t, dir, dir, env, "update", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("dir update after delete: %d %s", code, out)
	}
	code, out := runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl)
	if code != ExitOK {
		t.Fatalf("post-delete update check = %d, want 0 (deleted file must be pruned):\n%s", code, out)
	}
}

// TestEmptyDirInitAllowed verifies init on an empty directory succeeds
// with a warning (previously refused), and the resulting empty baseline
// checks clean.
func TestEmptyDirInitAllowed(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	code, out := runCLIIn(t, dir, dir, env, "init", "empty", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("empty-dir init = %d, want 0:\n%s", code, out)
	}
	if !contains(out, "empty baseline") {
		t.Fatalf("expected a warning on empty-dir init, got: %s", out)
	}
	code, out = runCLIIn(t, dir, dir, env, "check", "empty", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("check of empty baseline = %d, want 0:\n%s", code, out)
	}
}

// TestMissingBaselineMessage verifies check without a baseline exits 2
// with an actionable "run init first" message.
func TestMissingBaselineMessage(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"check", "logs", "--baseline", "nope.json")
	if code != ExitError {
		t.Fatalf("check before init = %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "baseline not found") || !strings.Contains(out, "nope.json") ||
		!strings.Contains(out, "run 'init' first") {
		t.Fatalf("missing-baseline message unclear:\n%s", out)
	}
}

// TestInitSingleFileSymlinkNoFollow verifies single-file init of a
// symlink records the link target and never hashes/follows the target.
func TestInitSingleFileSymlinkNoFollow(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	if err := os.WriteFile(target, []byte("secret content"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	code, out := runCLIIn(t, dir, dir, env, "init", "link.log", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("single-file symlink init: %d %s", code, out)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "b.json"))
	if strings.Contains(string(raw), `"hash"`) {
		t.Fatalf("single-file symlink init must not hash the target: %s", raw)
	}
	if !strings.Contains(string(raw), `"link_target"`) {
		t.Fatalf("expected link_target recorded in baseline: %s", raw)
	}
	// check of the symlink stays clean (no follow).
	code, out = runCLIIn(t, dir, dir, env, "check", "link.log", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("symlink single-file check: %d %s", code, out)
	}
}

// TestInitFormatJSON verifies init honors --format json with a JSON
// summary instead of the human-readable line.
func TestInitFormatJSON(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
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
	code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl, "--format", "json")
	if code != ExitOK {
		t.Fatalf("init --format json: %d %s", code, out)
	}
	if !strings.Contains(out, `"baseline"`) || !strings.Contains(out, `"files"`) || !strings.Contains(out, `"algorithm"`) {
		t.Fatalf("json init output missing fields: %s", out)
	}
	if strings.Contains(out, "baseline written:") {
		t.Fatalf("json init must not print the text summary: %s", out)
	}
}

// TestArgErrorConciseNoUsage verifies arg/flag errors exit 2 with a
// concise error line and never dump full usage text.
func TestArgErrorConciseNoUsage(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
	cases := [][]string{
		{"init", "a", "b"},      // too many args
		{"init"},                // missing arg
		{"check", "--zzz", "x"}, // unknown flag
		{"bogus-command"},       // unknown command
	}
	for _, args := range cases {
		code, out := runCLIIn(t, t.TempDir(), t.TempDir(), map[string]string{"IC_KEY": "k"}, args...)
		if code != ExitError {
			t.Errorf("%v exit = %d, want 2 (out=%q)", args, code, out)
		}
		if strings.Contains(out, "Usage:") {
			t.Errorf("%v printed usage text:\n%s", args, out)
		}
		if !strings.Contains(out, "error:") {
			t.Errorf("%v must print a concise error line: %q", args, out)
		}
	}
}

// TestKeyfileLoosePermsRefused verifies a group/world-readable keyfile is
// refused by default and accepted only with --allow-loose-keyfile.
func TestKeyfileLoosePermsRefused(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.log")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	kf := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(kf, []byte("filekey"), 0o644); err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "b.json")
	code, out := runCLIIn(t, dir, dir, map[string]string{},
		"init", dir, "--baseline", bl, "--keyfile", kf)
	if code != ExitError || !strings.Contains(out, "refusing") {
		t.Fatalf("loose keyfile init = %d, want refused:\n%s", code, out)
	}
	code, out = runCLIIn(t, dir, dir, map[string]string{},
		"init", dir, "--baseline", bl, "--keyfile", kf, "--allow-loose-keyfile")
	if code != ExitOK {
		t.Fatalf("loose keyfile with override = %d, want 0:\n%s", code, out)
	}
}

// TestIgnoreMtimeFlag verifies --ignore-mtime makes check content-only:
// an mtime-only change no longer triggers a modification.
func TestIgnoreMtimeFlag(t *testing.T) {
	// not parallel: t.Setenv/Chdir in harness
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
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(logs, "a.log"), future, future); err != nil {
		t.Fatal(err)
	}
	if code, _ := runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl); code != ExitChanges {
		t.Fatalf("mtime-only change without flag = %d, want 1", code)
	}
	code, out := runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl, "--ignore-mtime")
	if code != ExitOK {
		t.Fatalf("mtime-only change with --ignore-mtime = %d, want 0:\n%s", code, out)
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

// TestUpdateRejectsOutsideRoot verifies that `update` refuses a target
// outside the baseline root instead of writing "../x" entries that would
// make every later check report a false MISSING.
func TestUpdateRejectsOutsideRoot(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.log")
	if err := os.WriteFile(outside, []byte("O"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	code, out := runCLIIn(t, dir, dir, env, "update", outside, "--baseline", bl)
	if code != ExitError {
		t.Fatalf("outside-root update = %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "outside baseline root") {
		t.Fatalf("expected outside-root error, got: %s", out)
	}
	// A later check of the tree must stay clean: no "../outside.log" entry
	// may have leaked into the baseline.
	code, out = runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl)
	if code != ExitOK || strings.Contains(out, "MISSING") {
		t.Fatalf("check after rejected outside update = %d, want clean:\n%s", code, out)
	}
}

// TestUpdatePrunesDeletedSingleFile verifies that updating a path that
// no longer exists prunes its entry from the baseline instead of failing
// on Lstat and leaving it as a permanent MISSING.
func TestUpdatePrunesDeletedSingleFile(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "b.log"), []byte("B"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	if err := os.Remove(filepath.Join(logs, "b.log")); err != nil {
		t.Fatal(err)
	}
	// Updating the deleted file must prune it, not error out.
	code, out := runCLIIn(t, dir, dir, env, "update", filepath.Join(logs, "b.log"), "--baseline", bl)
	if code != ExitOK {
		t.Fatalf("update of deleted single file = %d, want 0:\n%s", code, out)
	}
	// check clean: b.log pruned, a.log still tracked.
	code, out = runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl)
	if code != ExitOK || strings.Contains(out, "MISSING") {
		t.Fatalf("post-delete check = %d, want clean:\n%s", code, out)
	}
}

// TestCheckUnreadableKeepsSiblings verifies that one unreadable file no
// longer aborts the whole check: readable siblings are still reported,
// the unreadable file is named (not MISSING), and the run exits 2.
func TestCheckUnreadableKeepsSiblings(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(logs, "secret.log")
	if err := os.WriteFile(secret, []byte("S"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(secret); err == nil {
		f.Close()
		t.Skip("running as root; permission checks are ineffective")
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o600) })

	code, out := runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl)
	if code != ExitError {
		t.Fatalf("unreadable check = %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "UNMODIFIED a.log") {
		t.Fatalf("readable sibling must still be reported:\n%s", out)
	}
	if !strings.Contains(out, "secret.log") {
		t.Fatalf("unreadable file must be named:\n%s", out)
	}
	if strings.Contains(out, "MISSING") {
		t.Fatalf("unreadable file must not be reported MISSING:\n%s", out)
	}
}

// TestCheckDeletedRootReportsMissing verifies that checking a root that
// has been deleted reports every baselined entry as MISSING (a finding,
// exit 1) instead of surfacing a raw stat error (M3).
func TestCheckDeletedRootReportsMissing(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "b.log"), []byte("B"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	if err := os.RemoveAll(logs); err != nil {
		t.Fatal(err)
	}
	code, out := runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl)
	if code != ExitChanges {
		t.Fatalf("check after deleting root = %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "MISSING") || !strings.Contains(out, "a.log") {
		t.Fatalf("deleted root must report MISSING entries:\n%s", out)
	}
}

// TestStaleBaselineTempExcludedFromScan verifies an orphaned baseline temp
// file (.baseline-*.tmp) inside the watched tree is auto-excluded and does
// not show up as a NEW result (M8).
func TestStaleBaselineTempExcludedFromScan(t *testing.T) {
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
	stale := filepath.Join(logs, ".baseline-deadbeef.tmp")
	if err := os.WriteFile(stale, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runCLIIn(t, dir, dir, env, "check", "logs", "--baseline", bl)
	if code != ExitOK {
		t.Fatalf("check with stale temp = %d, want 0 (temp must be excluded):\n%s", code, out)
	}
	if strings.Contains(out, ".baseline-deadbeef.tmp") || strings.Contains(out, "NEW") {
		t.Fatalf("stale temp file leaked into results:\n%s", out)
	}
}

// TestInitNonexistentPathWrapped verifies init of a nonexistent path exits
// 2 with an actionable "cannot scan <path>" message rather than a raw
// "lstat ...: no such file" leak (M13).
func TestInitNonexistentPathWrapped(t *testing.T) {
	dir := t.TempDir()
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"init", "does-not-exist", "--baseline", "b.json")
	if code != ExitError {
		t.Fatalf("init nonexistent = %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "cannot scan") || !strings.Contains(out, "does-not-exist") {
		t.Fatalf("expected wrapped 'cannot scan' error, got: %s", out)
	}
}

// TestInitSingleFileInTreeBaselineWarns verifies the in-tree baseline
// warning fires for a single-file init whose baseline sits next to the
// file (M16): the relative check must be against the parent dir, not the
// file itself.
func TestInitSingleFileInTreeBaselineWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IC_KEY": "k"}
	code, out := runCLIIn(t, dir, dir, env, "init", "f.txt", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	if !strings.Contains(out, "baseline is inside the watched tree") {
		t.Fatalf("single-file init with in-tree baseline must warn (M16): %s", out)
	}
}
