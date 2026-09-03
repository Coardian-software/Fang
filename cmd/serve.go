package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/aydocs/fang/internal/config"
	"github.com/aydocs/fang/internal/db"
	"github.com/aydocs/fang/internal/plugin"
	"github.com/aydocs/fang/internal/scheduler"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Fang scheduler daemon",
	Long:  "Starts the background scheduler that runs cron-based scan jobs. Writes a PID file to ~/.fang/serve.pid and drains in-flight scans on SIGINT/SIGTERM.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !flagQuiet {
			fmt.Println("[fang] starting scheduler daemon...")
		}

		home, _ := os.UserHomeDir()
		dbPath := filepath.Join(home, ".fang", "data", "fang.db")
		os.MkdirAll(filepath.Dir(dbPath), 0755)
		cfg := db.DefaultConfig()
		cfg.Path = dbPath
		db.Open(cfg)
		defer db.Close()

		config.Load()

		pluginDir := filepath.Join(home, ".fang", "plugins")
		pluginMgr := plugin.NewManager(pluginDir)
		pluginMgr.LoadAll()

		pidPath := filepath.Join(home, ".fang", "serve.pid")
		if err := writePIDFile(pidPath); err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		defer os.Remove(pidPath)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		s := scheduler.New()
		s.SetRootContext(ctx)
		if err := s.Start(); err != nil {
			return fmt.Errorf("scheduler start: %w", err)
		}
		defer s.Stop()

		fmt.Println("[fang] scheduler daemon running. Press Ctrl+C to stop.")

		<-ctx.Done()
		fmt.Println("[fang] shutdown signal received, draining in-flight scans...")
		return nil
	},
}

func writePIDFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("pid dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
		return fmt.Errorf("write pid: %w", err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
