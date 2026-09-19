package cmd

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/baseline"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/config"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/hash"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/walk"
)

// isatty reports whether stdout is a terminal (enables color by default).
func isatty() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func colorBool(flagColor bool, cfg config.Config) bool {
	if flagColor {
		return true
	}
	if cfg.Color != nil {
		return *cfg.Color
	}
	return isatty()
}

// loadConfigFor resolves the effective config for a command.
func loadConfigFor(cmd *cobra.Command) (config.Config, error) {
	path := cfgPath
	if path == "" {
		path = config.DefaultPath()
	}
	cfg, err := config.Load(path, cfgPath != "")
	if err != nil {
		return cfg, err
	}
	return cfg.Apply(flagsToOverrides(cmd)), nil
}

func flagsToOverrides(cmd *cobra.Command) config.FlagOverrides {
	var ov config.FlagOverrides
	if f := cmd.Flags().Lookup("baseline"); f != nil && f.Changed {
		v := f.Value.String()
		ov.Baseline = &v
	}
	if f := cmd.Flags().Lookup("algo"); f != nil && f.Changed {
		v := f.Value.String()
		ov.Algorithm = &v
	}
	if f := cmd.Flags().Lookup("format"); f != nil && f.Changed {
		v := f.Value.String()
		ov.Format = &v
	}
	if f := cmd.Flags().Lookup("quiet"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetBool("quiet")
		ov.Quiet = &v
	}
	if f := cmd.Flags().Lookup("workers"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetInt("workers")
		ov.Workers = &v
	}
	if f := cmd.Flags().Lookup("keyfile"); f != nil && f.Changed {
		v := f.Value.String()
		ov.KeyFile = &v
	}
	if f := cmd.Flags().Lookup("webhook"); f != nil && f.Changed {
		v := f.Value.String()
		ov.Webhook = &v
	}
	if f := cmd.Flags().Lookup("include"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetStringArray("include")
		ov.Include = v
	}
	if f := cmd.Flags().Lookup("exclude"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetStringArray("exclude")
		ov.Exclude = v
	}
	if f := cmd.Flags().Lookup("color"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetBool("color")
		ov.Color = &v
	}
	return ov
}

// loadRuntime resolves config, logger, HMAC key, store and algorithm.
func loadRuntime(cmd *cobra.Command) (*runtime, error) {
	cfg, err := loadConfigFor(cmd)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	lg, err := config.SetupLogger(cfg.LogFile, cfg.LogLevel)
	if err != nil {
		return nil, err
	}
	slog.SetDefault(lg)
	key, err := resolveKey(cfg)
	if err != nil {
		return nil, err
	}
	st, err := baseline.New(key)
	if err != nil {
		return nil, err
	}
	algo, err := model.ParseAlgorithm(cfg.Algorithm)
	if err != nil {
		return nil, err
	}
	return &runtime{cfg: cfg, log: lg, store: st, algo: algo}, nil
}

// resolveKey reads the HMAC key: env IC_KEY first, then keyfile.
// A group/world-readable keyfile leaks the signing secret to every local
// account; warn loudly but keep working (the file may be deliberately
// provisioned that way by the operator).
func resolveKey(cfg config.Config) ([]byte, error) {
	if env := os.Getenv("IC_KEY"); env != "" {
		return []byte(env), nil
	}
	if cfg.KeyFile != "" {
		if fi, err := os.Stat(cfg.KeyFile); err == nil && fi.Mode().Perm()&0o077 != 0 {
			slog.Warn("keyfile is group/world readable; store it 0600",
				slog.String("path", cfg.KeyFile),
				slog.String("mode", fmt.Sprintf("%04o", fi.Mode().Perm())))
		}
		b, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read keyfile: %w", err)
		}
		return bytes.TrimSpace(b), nil
	}
	return nil, fmt.Errorf("no HMAC key available: set IC_KEY or --keyfile")
}

func (r *runtime) scanOpts() walk.Options {
	opts := walk.Options{
		Algo:    r.algo,
		Include: r.cfg.Include,
		Exclude: r.cfg.Exclude,
		Workers: r.cfg.Workers,
	}
	// Auto-exclude the baseline file itself so a baseline stored inside
	// the tree it describes never flags its own path as new/modified.
	if abs, err := filepath.Abs(r.cfg.Baseline); err == nil {
		opts.ExcludePaths = append(opts.ExcludePaths, abs)
	}
	return opts
}

// scan hashes a path that may be a single file or a directory.
func (r *runtime) scan(path string) ([]model.Entry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		e, err := walk.StatEntry(abs, filepath.Base(abs))
		if err != nil {
			return nil, err
		}
		// One file: hash inline; a worker pool would start Workers
		// goroutines to process a single job.
		sum, err := hash.FileBuffer(abs, r.algo, make([]byte, 1<<20))
		if err != nil {
			return nil, err
		}
		e.Hash = sum
		return []model.Entry{*e}, nil
	}
	return walk.Scan(path, r.scanOpts())
}

// cmdColor returns the changed state of a bool flag (false if unset).
func cmdColor(cmd *cobra.Command, name string) bool {
	f := cmd.Flags().Lookup(name)
	if f == nil || !f.Changed {
		return false
	}
	v, _ := cmd.Flags().GetBool(name)
	return v
}

// stdout returns the standard output writer (indirected for tests).
var stdout = func() *os.File { return os.Stdout }

// runtime carries resolved per-run state.
type runtime struct {
	cfg   config.Config
	log   *slog.Logger
	store *baseline.Store
	algo  model.Algorithm
}
