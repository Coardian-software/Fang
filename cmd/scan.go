package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/aydocs/fang/internal/db"
	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/internal/pigment"
	"github.com/aydocs/fang/internal/report"
	"github.com/aydocs/fang/pkg/models"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan operations",
}

var scanRunCmd = &cobra.Command{
	Use:   "run [target]",
	Short: "Run a scan against a target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		modules, _ := cmd.Flags().GetStringSlice("modules")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		profile, _ := cmd.Flags().GetString("profile")
		proxy, _ := cmd.Flags().GetString("proxy")
		maxDepth, _ := cmd.Flags().GetInt("max-depth")
		maxPages, _ := cmd.Flags().GetInt("max-pages")
		crawlOn, _ := cmd.Flags().GetBool("crawl")
		allowPrivate, _ := cmd.Flags().GetBool("allow-private")
		aggressive, _ := cmd.Flags().GetBool("aggressive")
		rateLimit, _ := cmd.Flags().GetInt("rate-limit")
		format, _ := cmd.Flags().GetString("format")
		ciMode, _ := cmd.Flags().GetBool("ci")
		failOn, _ := cmd.Flags().GetString("fail-on")

		if format != "" && !report.IsValidFormat(format) {
			return fmt.Errorf("unknown format %q (valid: %s)", format, strings.Join(report.ValidFormats(), ", "))
		}
		failThreshold := models.Medium
		if ciMode {
			var err error
			failThreshold, err = report.ParseSeverity(failOn)
			if err != nil {
				return err
			}
		}

		if len(modules) > 0 {
			if err := validateModuleIDs(modules); err != nil {
				return err
			}
		}

		cfgOptions := []engine.Option{}
		if len(modules) > 0 {
			cfgOptions = append(cfgOptions, engine.WithModules(modules...))
		}
		if threads > 0 {
			cfgOptions = append(cfgOptions, engine.WithThreads(threads))
		}
		if timeout > 0 {
			cfgOptions = append(cfgOptions, engine.WithTimeout(time.Duration(timeout)*time.Second))
		}
		if proxy != "" {
			cfgOptions = append(cfgOptions, engine.WithProxy(proxy))
		}
		if maxDepth > 0 {
			cfgOptions = append(cfgOptions, engine.WithMaxDepth(maxDepth))
		}
		if maxPages > 0 {
			cfgOptions = append(cfgOptions, engine.WithMaxPages(maxPages))
		}
		if crawlOn {
			cfgOptions = append(cfgOptions, engine.WithCrawlEnabled(true))
		}
		if allowPrivate {
			cfgOptions = append(cfgOptions, engine.WithAllowPrivate(true))
		}
		if aggressive {
			cfgOptions = append(cfgOptions, engine.WithAggressive(true))
		}
		if rateLimit > 0 {
			cfgOptions = append(cfgOptions, engine.WithRateLimit(rateLimit))
		}
		cfg := engine.NewConfig(cfgOptions...)

		if profile != "" {
			profileModules := getProfileModules(profile)
			if len(profileModules) > 0 {
				cfgOptions = append(cfgOptions, engine.WithModules(profileModules...))
				cfg = engine.NewConfig(cfgOptions...)
			}
		}

		targetID, err := db.CreateTarget(target, "", "", "", "")
		if err != nil {
			return fmt.Errorf("create target: %w", err)
		}

		scanID, err := db.CreateScan(targetID, modules, cfg.Threads, int(cfg.Timeout.Seconds()), proxy, "cli", "")
		if err != nil {
			return fmt.Errorf("create scan: %w", err)
		}

		if !flagQuiet {
			pigment.New().Fg("#bd93f9").Bold().Fprintf(os.Stderr, "[fang] scan %s\n", target)
			pigment.New().Fg("#6272a4").Fprintf(os.Stderr, "scan id: %s\n", scanID)
			if len(modules) > 0 {
				pigment.New().Fg("#8be9fd").Fprintf(os.Stderr, "modules: %s\n", strings.Join(modules, ", "))
			}
		}

		db.UpdateScanStatus(scanID, "running", "")

		cfg.ScanID = scanID
		cfg.TargetID = targetID

		scanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		interrupted := false
		sigCtx, sigStop := signal.NotifyContext(scanCtx, os.Interrupt, syscall.SIGTERM)
		defer sigStop()
		go func() {
			<-sigCtx.Done()
			if errors.Is(sigCtx.Err(), context.Canceled) && scanCtx.Err() == nil {
				interrupted = true
			}
		}()

		eng := engine.New(cfg)
		result, err := eng.Run(scanCtx, target)
		if err != nil {
			reason := err.Error()
			if interrupted {
				reason = "interrupted"
			}
			db.UpdateScanStatus(scanID, "failed", reason)
			return fmt.Errorf("scan: %w", err)
		}

		db.UpdateScanStatus(scanID, "completed", "")

		if !flagQuiet {
			pigment.New().Fg("#50fa7b").Fprintf(os.Stderr, "scan completed: %d findings\n", len(result.Findings))
			pigment.New().Fg("#6272a4").Fprintf(os.Stderr, "scan id: %s\n", scanID)
		}

		if flagJSON && format == "" {
			format = "json"
		}
		switch {
		case format != "":
			if err := report.Write(cmd.Context(), os.Stdout, format, result); err != nil {
				return err
			}
		case !flagQuiet:
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SEVERITY\tMODULE\tTITLE\tURL")
			for _, f := range result.Findings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					paintSeverity(f.Severity), pigment.HiBlackString("%s", f.ModuleID), truncate(f.Title, 60), truncate(f.URL, 80))
			}
			w.Flush()
		}

		if ciMode {
			ciRequested = true
			exit := 0
			for _, f := range result.Findings {
				if report.SeverityAtLeast(f.Severity, failThreshold) {
					exit = 1
					break
				}
			}
			fmt.Fprintf(os.Stderr, "[fang] CI: %d finding(s) at or above %s (exit %d)\n",
				countAtLeast(result.Findings, failThreshold), failThreshold.String(), exit)
			db.Close()
			os.Exit(exit)
		}

		return nil
	},
}

func countAtLeast(findings []*models.Finding, threshold models.Severity) int {
	n := 0
	for _, f := range findings {
		if report.SeverityAtLeast(f.Severity, threshold) {
			n++
		}
	}
	return n
}

func validateModuleIDs(requested []string) error {
	valid := map[string]bool{}
	for _, m := range engine.GetRegistry().List() {
		valid[m.ID()] = true
	}
	var unknown []string
	for _, id := range requested {
		if !valid[id] {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	ids := make([]string, 0, len(valid))
	for id := range valid {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return fmt.Errorf("unknown module(s): %s\nvalid modules:\n  %s",
		strings.Join(unknown, ", "), strings.Join(ids, "\n  "))
}

var scanListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent scans",
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		scans, err := db.QueryScans(db.ScanFilter{Limit: limit})
		if err != nil {
			return err
		}

		if flagJSON {
			printJSON(scans)
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATUS\tTARGET\tMODULES\tCREATED")
		for _, s := range scans {
			target := ""
			t, err := db.GetTarget(s.TargetID)
			if err == nil {
				target = t.URL
			}
			modules := ""
			if s.Modules.Valid {
				modules = s.Modules.String
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				s.ID, paintStatus(s.Status), truncate(target, 50), truncate(modules, 40),
				s.CreatedAt.Format("2006-01-02 15:04"))
		}
		w.Flush()
		return nil
	},
}

var scanShowCmd = &cobra.Command{
	Use:   "show [scan-id]",
	Short: "Show scan details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scan, err := db.GetScan(args[0])
		if err != nil {
			return err
		}

		if flagJSON {
			printJSON(scan)
			return nil
		}

		target := ""
		t, err := db.GetTarget(scan.TargetID)
		if err == nil {
			target = t.URL
		}

		modules := ""
		if scan.Modules.Valid {
			modules = scan.Modules.String
		}
		proxy := ""
		if scan.Proxy.Valid {
			proxy = scan.Proxy.String
		}

		fmt.Printf("Scan ID:      %s\n", scan.ID)
		fmt.Printf("Status:       %s\n", scan.Status)
		fmt.Printf("Target:       %s\n", target)
		fmt.Printf("Modules:      %s\n", modules)
		fmt.Printf("Threads:      %d\n", scan.Threads)
		fmt.Printf("Timeout:      %d\n", scan.Timeout)
		fmt.Printf("Proxy:        %s\n", proxy)
		fmt.Printf("Created:      %s\n", scan.CreatedAt.Format(time.RFC3339))

		if scan.StartedAt.Valid {
			fmt.Printf("Started:      %s\n", scan.StartedAt.Time.Format(time.RFC3339))
		}
		if scan.FinishedAt.Valid {
			fmt.Printf("Finished:     %s\n", scan.FinishedAt.Time.Format(time.RFC3339))
		}
		if scan.Error.Valid && scan.Error.String != "" {
			fmt.Printf("Error:        %s\n", scan.Error.String)
		}
		return nil
	},
}

var scanCancelCmd = &cobra.Command{
	Use:   "cancel [scan-id]",
	Short: "Cancel a running scan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := db.UpdateScanStatus(args[0], "cancelled", "cancelled by user")
		if err != nil {
			return err
		}
		fmt.Printf("[fang] scan %s cancelled\n", args[0])
		return nil
	},
}

var scanDeleteCmd = &cobra.Command{
	Use:   "delete [scan-id]",
	Short: "Delete a scan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		d := db.DB()
		if d == nil {
			return fmt.Errorf("database not initialized")
		}
		_, err := d.Exec("DELETE FROM scans WHERE id = ?", args[0])
		if err != nil {
			return err
		}
		fmt.Printf("[fang] scan %s deleted\n", args[0])
		return nil
	},
}

func init() {
	scanRunCmd.Flags().StringSliceP("modules", "m", nil, "modules to run (default: all)")
	scanRunCmd.Flags().IntP("threads", "t", 20, "number of concurrent threads")
	scanRunCmd.Flags().IntP("timeout", "T", 600, "scan timeout in seconds")
	scanRunCmd.Flags().StringP("profile", "p", "", "scan profile (quick, passive, api, infra, full)")
	scanRunCmd.Flags().String("proxy", "", "proxy URL (http://host:port)")
	scanRunCmd.Flags().Int("rate-limit", 0, "global requests-per-second cap on the shared HTTP client")
	scanRunCmd.Flags().Int("max-depth", 2, "maximum crawl depth")
	scanRunCmd.Flags().Int("max-pages", 200, "maximum pages to crawl")
	scanRunCmd.Flags().Bool("crawl", false, "enable crawl-first stage: discovers linked pages and scans each (multiplies runtime by page count)")
	scanRunCmd.Flags().Bool("allow-private", false, "permit scanning loopback, RFC1918 and link-local targets")
	scanRunCmd.Flags().Bool("aggressive", false, "enable mutating (non-GET) probes and intrusive checks")
	scanRunCmd.Flags().String("format", "", "output format (json, sarif, markdown, csv, jsonl, pdf)")
	scanRunCmd.Flags().Bool("ci", false, "CI mode: exit 1 when findings meet --fail-on threshold")
	scanRunCmd.Flags().String("fail-on", "medium", "severity threshold for --ci (info, low, medium, high, critical)")

	scanListCmd.Flags().IntP("limit", "l", 20, "number of scans to show")

	scanCmd.AddCommand(scanRunCmd)
	scanCmd.AddCommand(scanListCmd)
	scanCmd.AddCommand(scanShowCmd)
	scanCmd.AddCommand(scanCancelCmd)
	scanCmd.AddCommand(scanDeleteCmd)

	rootCmd.AddCommand(scanCmd)
}
