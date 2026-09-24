// Package config loads YAML configuration with CLI flag overrides and
// provides structured logging setup.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// Config is the user-facing configuration. CLI flags override file values
// only when explicitly set by the caller (mergeFromFlags).
type Config struct {
	Baseline   string   `yaml:"baseline"`
	Algorithm  string   `yaml:"algorithm"`
	Include    []string `yaml:"include"`
	Exclude    []string `yaml:"exclude"`
	Format     string   `yaml:"format"`
	Color      *bool    `yaml:"color"`
	Quiet      bool     `yaml:"quiet"`
	LogFile    string   `yaml:"log_file"`
	LogLevel   string   `yaml:"log_level"`
	WebhookURL string   `yaml:"webhook_url"`
	KeyFile    string   `yaml:"key_file"`
	Workers    int      `yaml:"workers"`
	// FollowSymlinks opts into hashing symlink targets on scan.
	FollowSymlinks bool `yaml:"follow_symlinks"`
	// AllowLooseKeyfile permits a group/world-readable keyfile (default: refuse).
	AllowLooseKeyfile bool `yaml:"allow_loose_keyfile"`
	// IgnoreMtime compares content (hash) only, ignoring metadata.
	IgnoreMtime bool `yaml:"ignore_mtime"`
}

// Default returns the built-in defaults. The default Baseline path is
// relative to the current working directory; use an absolute value (in
// --baseline or config `baseline:`) for a stable location regardless of
// where the command runs (L2).
func Default() Config {
	return Config{
		Baseline:  "integrity-baseline.json",
		Algorithm: "sha256",
		Format:    "text",
		Workers:   0, // NumCPU
	}
}

// DefaultPath is the config file looked up when --config is not given.
func DefaultPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "integrity-check", "config.yaml")
	}
	return "integrity-check.yaml"
}

// Load reads path (YAML) and overlays it on defaults. Missing file is
// not an error when path is the default location; explicit --config
// failures are errors (missing flag tells the caller).
func Load(path string, required bool) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config: %w", err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// FlagOverrides carries only flags the user actually set.
type FlagOverrides struct {
	Baseline          *string
	Algorithm         *string
	Format            *string
	Color             *bool
	Quiet             *bool
	Workers           *int
	KeyFile           *string
	Webhook           *string
	FollowSymlinks    *bool
	AllowLooseKeyfile *bool
	IgnoreMtime       *bool
	Include           []string // appended to file values
	Exclude           []string
}

// Apply merges non-nil overrides onto cfg.
func (cfg Config) Apply(o FlagOverrides) Config {
	if o.Baseline != nil {
		cfg.Baseline = *o.Baseline
	}
	if o.Algorithm != nil {
		cfg.Algorithm = *o.Algorithm
	}
	if o.Format != nil {
		cfg.Format = *o.Format
	}
	if o.Color != nil {
		cfg.Color = o.Color
	}
	if o.Quiet != nil {
		cfg.Quiet = *o.Quiet
	}
	if o.Workers != nil {
		cfg.Workers = *o.Workers
	}
	if o.KeyFile != nil {
		cfg.KeyFile = *o.KeyFile
	}
	if o.Webhook != nil {
		cfg.WebhookURL = *o.Webhook
	}
	if o.FollowSymlinks != nil {
		cfg.FollowSymlinks = *o.FollowSymlinks
	}
	if o.AllowLooseKeyfile != nil {
		cfg.AllowLooseKeyfile = *o.AllowLooseKeyfile
	}
	if o.IgnoreMtime != nil {
		cfg.IgnoreMtime = *o.IgnoreMtime
	}
	if len(o.Include) > 0 {
		cfg.Include = append(cfg.Include, o.Include...)
	}
	if len(o.Exclude) > 0 {
		cfg.Exclude = append(cfg.Exclude, o.Exclude...)
	}
	return cfg
}

// Validate checks semantic correctness of the configuration.
func (cfg Config) Validate() error {
	switch cfg.Format {
	case "", "text", "json":
	default:
		return fmt.Errorf("config: invalid format %q (want text or json)", cfg.Format)
	}
	switch cfg.Algorithm {
	case "", "sha256", "sha512", "blake2b":
	default:
		return fmt.Errorf("config: invalid algorithm %q (want sha256, sha512, blake2b)", cfg.Algorithm)
	}
	if cfg.Workers < 0 {
		return fmt.Errorf("config: workers must be >= 0, got %d", cfg.Workers)
	}
	if cfg.Baseline == "" {
		return fmt.Errorf("config: baseline path must not be empty")
	}
	for _, pat := range append(append([]string{}, cfg.Include...), cfg.Exclude...) {
		if !doublestar.ValidatePattern(pat) {
			return fmt.Errorf("config: invalid glob %q", pat)
		}
	}
	return nil
}

// SetupLogger returns a slog logger writing to LogFile (or stderr when
// empty) at the given level ("debug", "info", "warn", "error"). The
// returned closeFunc closes the underlying file when one was opened
// (no-op for stderr), so callers can release the handle (Windows cannot
// delete/lock a file that is still open).
func SetupLogger(logFile, level string) (lg *slog.Logger, closeFunc func() error, err error) {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "", "info":
		lv = slog.LevelInfo
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, nil, fmt.Errorf("config: unknown log level %q", level)
	}
	var w = os.Stderr
	closeFunc = func() error { return nil }
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("config: open log file: %w", err)
		}
		w = f
		closeFunc = f.Close
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lv})), closeFunc, nil
}
