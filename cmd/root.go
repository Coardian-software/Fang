package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aydocs/fang/internal/db"
	"github.com/spf13/cobra"
)

var (
	Version     = "dev"
	flagOutput  string
	flagJSON    bool
	flagQuiet   bool
	ciRequested bool
)

var rootCmd = &cobra.Command{
	Use:           "fang",
	Version:       Version,
	Short:         "Fang - Web Application Security Scanner",
	Long:          "Fang is a crawl-first web exposure linter with a calibrated, focused module portfolio.",
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		uiSetup()
		home, _ := os.UserHomeDir()
		dbPath := os.Getenv("FANG_DB_PATH")
		if dbPath == "" {
			dbPath = home + "/.fang/data/fang.db"
		}
		if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
			return fmt.Errorf("create data directory: %w", err)
		}
		cfg := db.DefaultConfig()
		cfg.Path = dbPath
		if _, err := db.Open(cfg); err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		db.Close()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		uiError("%v", err)
		code := 1
		if ciRequested {
			code = 2
		}
		db.Close()
		os.Exit(code)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "", "output format (json, table, csv)")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "output as JSON")
	rootCmd.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "suppress non-essential output")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable all terminal color output")
}
