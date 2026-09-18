package cmd

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"os"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/watch"
)

// newWatchCmd builds the watch subcommand (fsnotify, alert webhook).
func newWatchCmd() *cobra.Command {
	var algoFlag, format string
	var webhook string
	var debounce time.Duration
	cmd := &cobra.Command{
		Use:   "watch <path>",
		Short: "Watch files in real time and alert on change",
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
			url := r.cfg.WebhookURL
			if f := c.Flags().Lookup("webhook"); f != nil && f.Changed {
				url = webhook
			}
			wcfg := watch.Config{
				Root:       args[0],
				ScanOpts:   r.scanOpts(),
				Baseline:   base,
				Store:      r.store,
				BaselinePk: r.cfg.Baseline,
				WebhookURL: url,
				Debounce:   debounce,
				Out:        stdout(),
				Log:        r.log,
			}
			return watch.Run(cmdCtx(), wcfg)
		},
	}
	addAlgoFlag(cmd, &algoFlag)
	addFormatFlag(cmd, &format)
	cmd.Flags().StringVar(&webhook, "webhook", "", "webhook URL for tamper alerts")
	cmd.Flags().DurationVar(&debounce, "debounce", 500*time.Millisecond, "debounce window for fs events")
	return cmd
}

// cmdCtx returns a context cancelled on SIGINT/SIGTERM.
func cmdCtx() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx
}
