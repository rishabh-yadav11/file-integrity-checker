package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/report"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/walk"
)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init <path>",
		Short: "Create the baseline for a file or directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			r, err := loadRuntime(c)
			if err != nil {
				return err
			}
			entries, err := r.scan(args[0])
			if err != nil {
				return err
			}
			abs, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			// A single-file baseline is parent-rooted: the entry is
			// stored under the file's base name relative to its
			// directory, so `check`/`update` of the same file (or its
			// directory) resolve paths consistently.
			root := abs
			if info, statErr := os.Stat(abs); statErr == nil && !info.IsDir() {
				root = filepath.Dir(abs)
			}
			b := model.Baseline{
				Version:   model.BaselineVersion,
				Algorithm: r.algo,
				CreatedAt: time.Now(),
				Root:      root,
				Entries:   entries,
			}
			if err := r.store.Save(r.cfg.Baseline, b); err != nil {
				return err
			}
			// A baseline stored inside the tree it describes is
			// self-referential: every Save changes it, so every later
			// check flags it as modified. Warn so the operator notices
			// before building automation on a perpetually-failing check.
			absBase, _ := filepath.Abs(r.cfg.Baseline)
			if rel, err := filepath.Rel(abs, absBase); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
				r.log.Warn("baseline is inside the watched tree; it will be re-baselined and flagged as modified on every run - store it outside the tree",
					slog.String("baseline", r.cfg.Baseline),
					slog.String("root", abs))
			}
			_, _ = fmt.Fprintf(os.Stdout, "baseline written: %s (%d files, %s)\n", r.cfg.Baseline, len(entries), r.algo)
			return nil
		},
	}
	return cmd
}

func newCheckCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "check <path>",
		Short: "Compare current state against the baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			r, err := loadRuntime(c)
			if err != nil {
				return err
			}
			base, err := r.store.Load(r.cfg.Baseline)
			if err != nil {
				return err
			}
			// Default --algo to the baseline's own algorithm: the hashes
			// are already labeled there, so requiring a repeat of --algo
			// on every check of a non-sha256 baseline is a footgun. An
			// explicitly set --algo still overrides and the mismatch
			// guard in walk.Compare still rejects wrong requests.
			if f := c.Flags().Lookup("algo"); f == nil || !f.Changed {
				r.algo = base.Algorithm
			}
			results, err := walk.Compare(args[0], base, r.scanOpts())
			if err != nil {
				return err
			}
			co := report.Options{
				Format: r.cfg.Format,
				Color:  colorBool(cmdColor(c, "color"), r.cfg),
				Quiet:  r.cfg.Quiet,
			}
			if err := report.Render(stdout(), results, co); err != nil {
				return err
			}
			s := report.Count(results)
			// Quiet mode (like AIDE -q) is for CI/cron: silence the
			// per-file Unmodified lines (report) and the trailing
			// summary on a clean tree. Changes always print so the
			// operator sees what moved, and the exit code still works.
			if r.cfg.Format != "json" && (!r.cfg.Quiet || s.Changed()) {
				_, _ = fmt.Fprintln(stdout(), s.Text())
			}
			if s.Changed() {
				return errChangesFound
			}
			return nil
		},
	}
	return cmd
}

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update <path>",
		Short: "Accept current state into the baseline (file or dir)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			r, err := loadRuntime(c)
			if err != nil {
				return err
			}
			// Merge-update: accept current state of <path> without
			// orphaning the rest of the tree. Fresh entries rebase onto
			// the baseline root, replace any baseline entries under the
			// updated path (including ones that vanished), and leave all
			// other baseline entries untouched.
			base, err := r.store.Load(r.cfg.Baseline)
			if err != nil {
				return err
			}
			// A baseline must hold one consistent algorithm. A partial
			// update with a different --algo would store new hashes in
			// one algorithm, leave untouched entries under the old one,
			// and flip the top-level label: every later check would
			// false-positive on the untouched files. Refuse instead.
			if r.algo != base.Algorithm {
				return fmt.Errorf("update: baseline uses %s; refusing to write %s hashes into it (re-init with --algo %s to switch algorithms)", base.Algorithm, r.algo, r.algo)
			}
			// Legacy single-file baselines stored Root as the file
			// itself; their entries are keyed by base name relative to
			// the parent dir. Treat the parent as the effective root so
			// updates merge under the right paths instead of writing
			// "../"-prefixed entries.
			abs, absErr := filepath.Abs(args[0])
			if absErr != nil {
				return absErr
			}
			if stat, statErr := os.Stat(abs); statErr == nil && !stat.IsDir() && base.Root == abs {
				base.Root = filepath.Dir(abs)
			}
			entries, err := r.scan(args[0])
			if err != nil {
				return err
			}
			prefix := ""
			if rel, relErr := filepath.Rel(base.Root, abs); relErr == nil {
				if s := filepath.ToSlash(rel); s != "." {
					prefix = s + "/"
				}
			} else {
				return fmt.Errorf("update: %s is outside baseline root %s", abs, base.Root)
			}
			// Determine whether args[0] is a file or directory, and the
			// exact relative path of a single-file target, so the merge
			// below prunes only what is actually in scope.
			info, statErr := os.Stat(abs)
			dirUpdate := true
			if statErr == nil && !info.IsDir() {
				dirUpdate = false
			}
			relTarget := ""
			if !dirUpdate {
				// Single-file update: scan() names the entry by base
				// name, so it maps onto the file's own directory inside
				// the baseline root, not under a nested dir of itself.
				dirRel := filepath.ToSlash(filepath.Dir(abs))
				relDir, relErr := filepath.Rel(base.Root, dirRel)
				if relErr != nil {
					return fmt.Errorf("update: %s is outside baseline root %s", abs, base.Root)
				}
				if s := filepath.ToSlash(relDir); s == "." {
					prefix = ""
				} else {
					prefix = s + "/"
				}
				relTarget = prefix + filepath.Base(abs)
			}
			for i := range entries {
				entries[i].Path = prefix + entries[i].Path
			}
			fresh := make(map[string]struct{}, len(entries))
			for _, e := range entries {
				fresh[e.Path] = struct{}{}
			}
			merged := make([]model.Entry, 0, len(base.Entries)+len(entries))
			for _, e := range base.Entries {
				_, accepted := fresh[e.Path]
				var inside bool
				if dirUpdate {
					// Directory update: any entry under the updated dir
					// (the whole root when prefix == "") that no longer
					// exists is pruned; kept siblings stay untouched.
					inside = prefix == "" || e.Path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(e.Path, prefix)
				} else {
					// Single-file update: only the file's own entry is in
					// scope; siblings in the same directory are preserved.
					inside = e.Path == relTarget
				}
				if inside && !accepted {
					continue // vanished under the updated path
				}
				if !accepted {
					merged = append(merged, e)
				}
			}
			merged = append(merged, entries...)
			b := model.Baseline{
				Version:   model.BaselineVersion,
				Algorithm: r.algo,
				CreatedAt: time.Now(),
				Root:      base.Root,
				Entries:   merged,
			}
			if err := r.store.Save(r.cfg.Baseline, b); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout(), "baseline updated: %s (%d files accepted, %d total)\n", r.cfg.Baseline, len(entries), len(merged))
			return nil
		},
	}
	return cmd
}

func newVerifyBaselineCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-baseline",
		Short: "Verify the baseline HMAC (untampered?)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			r, err := loadRuntime(c)
			if err != nil {
				return err
			}
			if _, err := r.store.Load(r.cfg.Baseline); err != nil {
				return err
			}
			// Perms 0600 are part of the contract (goal: baseline 0600).
			// A group/world-readable baseline leaks its contents and
			// structure; warn loudly but keep the verdict accurate.
			if fi, err := os.Stat(r.cfg.Baseline); err == nil && fi.Mode().Perm()&0o077 != 0 {
				r.log.Warn("baseline file is group/world readable; store it 0600",
					slog.String("path", r.cfg.Baseline),
					slog.String("mode", fmt.Sprintf("%04o", fi.Mode().Perm())))
			}
			_, _ = fmt.Fprintln(stdout(), "baseline OK")
			return nil
		},
	}
}
