package cmd

import (
	"os"

	"github.com/aydocs/fang/internal/db"
	"github.com/spf13/cobra"
)

var (
	flagOutput  string
	flagJSON    bool
	flagQuiet   bool
	ciRequested bool
)

var rootCmd = &cobra.Command{
	Use:           "fang",
	Short:         "Fang - Web Application Security Scanner",
	Long:          "Fang is a crawl-first web exposure linter with a calibrated, focused module portfolio.",
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		uiSetup()
		home, _ := os.UserHomeDir()
		dbPath := home + "/.fang/data/fang.db"
		os.MkdirAll(home+"/.fang/data", 0755)
		cfg := db.DefaultConfig()
		cfg.Path = dbPath
		db.Open(cfg)
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
