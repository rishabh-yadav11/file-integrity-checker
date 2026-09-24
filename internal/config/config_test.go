package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultValid(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestLoadYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	yamlBody := `
baseline: /var/lib/ic/baseline.json
algorithm: sha512
include:
  - "**/*.log"
exclude:
  - "*.tmp"
format: json
quiet: true
workers: 8
`
	if err := os.WriteFile(p, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Baseline != "/var/lib/ic/baseline.json" {
		t.Errorf("baseline = %q", cfg.Baseline)
	}
	if cfg.Algorithm != "sha512" {
		t.Errorf("algorithm = %q", cfg.Algorithm)
	}
	if len(cfg.Include) != 1 || cfg.Include[0] != "**/*.log" {
		t.Errorf("include = %v", cfg.Include)
	}
	if !cfg.Quiet || cfg.Workers != 8 {
		_ = cfg.Workers
	}
	if cfg.Workers != 8 {
		t.Errorf("workers = %d, want 8", cfg.Workers)
	}
	if cfg.Format != "json" {
		t.Errorf("format = %q", cfg.Format)
	}
}

func TestLoadMissingNotRequired(t *testing.T) {
	t.Parallel()
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), false)
	if err != nil {
		t.Fatalf("missing optional config should be fine: %v", err)
	}
	def := Default()
	if cfg.Baseline != def.Baseline || cfg.Algorithm != def.Algorithm || cfg.Format != def.Format || cfg.Workers != def.Workers {
		t.Fatalf("missing file should yield defaults, got %+v", cfg)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	t.Parallel()
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), true); err == nil {
		t.Fatal("expected error for required missing config")
	}
}

func TestLoadGarbage(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("{{{not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, true); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestFlagOverrides(t *testing.T) {
	t.Parallel()
	cfg := Default()
	b := "/new/baseline.json"
	a := "sha512"
	f := "json"
	q := true
	w := 7
	k := "/path/key"
	hook := "http://example/hook"
	merged := cfg.Apply(FlagOverrides{
		Baseline:  &b,
		Algorithm: &a,
		Format:    &f,
		Quiet:     &q,
		Workers:   &w,
		KeyFile:   &k,
		Webhook:   &hook,
		Include:   []string{"x/**"},
		Exclude:   []string{"y/**"},
	})
	if merged.Baseline != b || merged.Algorithm != a || merged.Format != f || !merged.Quiet || merged.Workers != 7 {
		t.Fatalf("overrides not applied: %+v", merged)
	}
	if len(merged.Include) != 1 || merged.Include[0] != "x/**" {
		t.Fatalf("include merge failed: %v", merged.Include)
	}
	// Nil overrides leave values untouched.
	untouched := cfg.Apply(FlagOverrides{})
	if untouched.Baseline != cfg.Baseline {
		t.Fatalf("nil override changed baseline: %q", untouched.Baseline)
	}
}

func TestValidateErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{"bad format", func(c *Config) { c.Format = "xml" }},
		{"bad algo", func(c *Config) { c.Algorithm = "md5" }},
		{"neg workers", func(c *Config) { c.Workers = -1 }},
		{"empty baseline", func(c *Config) { c.Baseline = "" }},
		{"invalid include glob", func(c *Config) { c.Include = []string{"[unclosed"} }},
		{"invalid exclude glob", func(c *Config) { c.Exclude = []string{"a/**/b["} }},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			tt.mut(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSetupLogger(t *testing.T) {
	t.Parallel()
	// stderr logger
	lg, _, err := SetupLogger("", "debug")
	if err != nil {
		t.Fatal(err)
	}
	lg.Debug("hello", "k", 1)
	// file logger
	p := filepath.Join(t.TempDir(), "ic.log")
	lg2, close2, err := SetupLogger(p, "warn")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = close2() }()
	lg2.Info("should-not-appear") // below level
	lg2.Warn("should-appear")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("log file empty")
	}
	if string(raw) != "" && !containsLevel(string(raw), "should-appear") {
		t.Fatalf("log file missing warn line: %q", string(raw))
	}
	if containsLevel(string(raw), "should-not-appear") {
		t.Fatal("info line written at warn level")
	}
	// bad level
	if _, _, err := SetupLogger("", "chatty"); err == nil {
		t.Fatal("expected error for unknown level")
	}
}

func containsLevel(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestSetupLoggerToFile verifies SetupLogger writes to the configured log
// file and rejects unknown levels.
func TestSetupLoggerToFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "log.txt")
	lg, closeFn, err := SetupLogger(f, "debug")
	if err != nil {
		t.Fatalf("SetupLogger: %v", err)
	}
	defer func() { _ = closeFn() }()
	lg.Info("hello")
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if _, _, err := SetupLogger("", "bogus"); err == nil {
		t.Fatal("unknown level must error")
	}
}
