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

// resolveColor computes the effective color setting. Precedence (L8):
// NO_COLOR forces it off; then an explicitly-set --color flag (true or
// false) wins; then the config file value; then the tty default.
func resolveColor(flagSet, flagVal bool, cfg config.Config) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if flagSet {
		return flagVal
	}
	if cfg.Color != nil {
		return *cfg.Color
	}
	return isatty()
}

// cmdColorSet reports whether the --color flag was explicitly changed.
func cmdColorSet(cmd *cobra.Command, name string) bool {
	f := cmd.Flags().Lookup(name)
	return f != nil && f.Changed
}

// cmdColorVal returns the --color flag's current value.
func cmdColorVal(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
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
	if f := cmd.Flags().Lookup("allow-loose-keyfile"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetBool("allow-loose-keyfile")
		ov.AllowLooseKeyfile = &v
	}
	if f := cmd.Flags().Lookup("webhook"); f != nil && f.Changed {
		v := f.Value.String()
		ov.Webhook = &v
	}
	if f := cmd.Flags().Lookup("follow-symlinks"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetBool("follow-symlinks")
		ov.FollowSymlinks = &v
	}
	if f := cmd.Flags().Lookup("ignore-mtime"); f != nil && f.Changed {
		v, _ := cmd.Flags().GetBool("ignore-mtime")
		ov.IgnoreMtime = &v
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
// account; it is refused by default unless --allow-loose-keyfile is given.
func resolveKey(cfg config.Config) ([]byte, error) {
	if env := os.Getenv("IC_KEY"); env != "" {
		if cfg.KeyFile != "" {
			// Both configured: IC_KEY silently beating the keyfile is
			// the kind of surprise that ships the wrong secret. Warn so
			// the operator can drop one of them (M9).
			slog.Warn("IC_KEY and keyfile are both set; IC_KEY takes precedence",
				slog.String("keyfile", cfg.KeyFile))
		}
		return []byte(env), nil
	}
	if cfg.KeyFile != "" {
		if fi, err := os.Stat(cfg.KeyFile); err == nil && loosePerms(fi) {
			if !cfg.AllowLooseKeyfile {
				return nil, fmt.Errorf("keyfile %s is group/world readable (mode %04o); refusing - re-chmod it to 0600 or pass --allow-loose-keyfile to override",
					cfg.KeyFile, fi.Mode().Perm())
			}
			slog.Warn("keyfile is group/world readable (override enabled); store it 0600",
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

// loadBaseline loads the baseline, wrapping a missing file with an
// actionable "run init first" message, and warns when the baseline file
// is group/world readable.
func (r *runtime) loadBaseline() (model.Baseline, error) {
	b, err := r.store.Load(r.cfg.Baseline)
	if err != nil {
		if os.IsNotExist(err) {
			return b, fmt.Errorf("baseline not found: %s (run 'init' first)", r.cfg.Baseline)
		}
		return b, err
	}
	if fi, serr := os.Stat(r.cfg.Baseline); serr == nil && loosePerms(fi) {
		r.log.Warn("baseline file is group/world readable; store it 0600",
			slog.String("path", r.cfg.Baseline),
			slog.String("mode", fmt.Sprintf("%04o", fi.Mode().Perm())))
	}
	return b, nil
}

func (r *runtime) scanOpts() walk.Options {
	opts := walk.Options{
		Algo:           r.algo,
		Include:        r.cfg.Include,
		Exclude:        r.cfg.Exclude,
		Workers:        r.cfg.Workers,
		FollowSymlinks: r.cfg.FollowSymlinks,
		IgnoreMtime:    r.cfg.IgnoreMtime,
		Warn: func(format string, args ...any) {
			r.log.Warn(fmt.Sprintf(format, args...))
		},
	}
	// Auto-exclude the baseline file itself so a baseline stored inside
	// the tree it describes never flags its own path as new/modified.
	if abs, err := filepath.Abs(r.cfg.Baseline); err == nil {
		opts.ExcludePaths = append(opts.ExcludePaths, abs)
	}
	// Auto-exclude the atomic-write temp files (.baseline-*.tmp) too: a
	// stale one left by a crashed Save would otherwise show up as a NEW
	// entry in scans (M8).
	opts.Exclude = append(opts.Exclude, ".baseline-*.tmp")
	return opts
}

// scan hashes a path that may be a single file or a directory.
func (r *runtime) scan(path string) ([]model.Entry, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot scan %s: %w", path, err)
	}
	// Symlinks are never followed for a single-file init: record the
	// link target instead of hashing through it. A symlink to a
	// directory is rejected explicitly.
	if info.Mode()&os.ModeSymlink != 0 {
		if fi, serr := os.Stat(path); serr == nil && fi.IsDir() {
			return nil, fmt.Errorf("%s is a symlink to a directory; use the real directory path", path)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		e, err := walk.StatEntry(abs, filepath.Base(abs))
		if err != nil {
			return nil, err
		}
		return []model.Entry{*e}, nil
	}
	if info.IsDir() {
		return walk.Scan(path, r.scanOpts())
	}
	// FIFOs, sockets, devices: never open them (a FIFO read would block).
	// As a single init target they cannot be hashed, so refusing beats
	// silently writing an empty baseline (M4).
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to init %s: not a regular file (type %v)", path, info.Mode())
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	e, err := walk.StatEntry(abs, filepath.Base(abs))
	if err != nil {
		return nil, err
	}
	// One file: hash inline; a worker pool would start Workers
	// goroutines to process a single job. hash.File reuses the shared
	// chunkSize buffer (Q3).
	sum, err := hash.File(abs, r.algo)
	if err != nil {
		return nil, err
	}
	e.Hash = sum
	e.Algorithm = r.algo
	return []model.Entry{*e}, nil
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
