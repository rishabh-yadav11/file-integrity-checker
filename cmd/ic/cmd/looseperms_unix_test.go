//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyBaselineWarnsOnLoosePerms verifies verify-baseline warns once
// (not twice, M12) when the baseline is group/world readable but still
// reports OK. POSIX-only: Windows has no meaningful perms bits, so the
// warning never fires there (H6).
func TestVerifyBaselineWarnsOnLoosePerms(t *testing.T) {
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
	loose := filepath.Join(dir, "b.json")
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"}, "verify-baseline", "--baseline", "b.json")
	if code != ExitOK || !strings.Contains(out, "baseline OK") {
		t.Fatalf("verify loose = %d\n%s", code, out)
	}
	if n := strings.Count(out, "group/world readable"); n != 1 {
		t.Fatalf("loose-perms warning printed %d times, want exactly 1 (M12):\n%s", n, out)
	}
	// Tight perms: no warning.
	if err := os.Chmod(filepath.Join(dir, "b.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out = runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"}, "verify-baseline", "--baseline", "b.json")
	if strings.Contains(out, "group/world readable") {
		t.Fatalf("unexpected perms warning for 0600 baseline: %s", out)
	}
}
