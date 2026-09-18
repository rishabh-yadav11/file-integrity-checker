package config

import (
	"path/filepath"
	"testing"
)

// TestDefaultPath covers both branches of DefaultPath: the normal
// home-based lookup and the fallback when UserHomeDir fails.
func TestDefaultPath(t *testing.T) {
	// Primary branch: HOME set to a temp dir.
	t.Setenv("HOME", t.TempDir())
	p := DefaultPath()
	if filepath.Base(p) != "config.yaml" {
		t.Fatalf("DefaultPath = %q, want config.yaml base", p)
	}
	if filepath.Base(filepath.Dir(filepath.Dir(p))) != ".config" {
		t.Fatalf("DefaultPath = %q, want under .config", p)
	}

	// Fallback branch: unset every env var UserHomeDir consults.
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	p = DefaultPath()
	if filepath.Base(p) != "integrity-check.yaml" {
		t.Fatalf("DefaultPath fallback = %q, want integrity-check.yaml", p)
	}
}
