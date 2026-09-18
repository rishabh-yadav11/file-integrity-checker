package cmd

import (
	"fmt"
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
			abs, _ := filepath.Abs(args[0])
			b := model.Baseline{
				Version:   model.BaselineVersion,
				Algorithm: r.algo,
				CreatedAt: time.Now(),
				Root:      abs,
				Entries:   entries,
			}
			if err := r.store.Save(r.cfg.Baseline, b); err != nil {
				return err
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
			if r.cfg.Format != "json" {
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
			entries, err := r.scan(args[0])
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
			abs, err := filepath.Abs(args[0])
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
			if info, statErr := os.Stat(abs); statErr == nil && !info.IsDir() {
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
				inside := prefix != "" && (e.Path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(e.Path, prefix))
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
			_, _ = fmt.Fprintln(stdout(), "baseline OK")
			return nil
		},
	}
}
