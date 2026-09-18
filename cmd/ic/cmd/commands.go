package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/report"
	"github.com/rishabh-yadav11/file-integrity-checker/internal/walk"
)

func newInitCmd() *cobra.Command {
	var algoFlag, format string
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
			fmt.Fprintf(os.Stdout, "baseline written: %s (%d files, %s)\n", r.cfg.Baseline, len(entries), r.algo)
			return nil
		},
	}
	addAlgoFlag(cmd, &algoFlag)
	addFormatFlag(cmd, &format)
	return cmd
}

func newCheckCmd() *cobra.Command {
	var algoFlag, format string

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
				fmt.Fprintln(stdout(), s.Text())
			}
			if s.Changed() {
				return errChangesFound
			}
			return nil
		},
	}
	addAlgoFlag(cmd, &algoFlag)
	addFormatFlag(cmd, &format)
	cmd.Flags().Bool("color", isatty(), "colorize output")
	cmd.Flags().BoolP("quiet", "q", false, "hide unmodified lines")
	return cmd
}

func newUpdateCmd() *cobra.Command {
	var algoFlag, format string
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
			fmt.Fprintf(stdout(), "baseline updated: %s (%d files)\n", r.cfg.Baseline, len(entries))
			return nil
		},
	}
	addAlgoFlag(cmd, &algoFlag)
	addFormatFlag(cmd, &format)
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
			fmt.Fprintln(stdout(), "baseline OK")
			return nil
		},
	}
}
