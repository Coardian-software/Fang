package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aydocs/fang/internal/db"
	"github.com/spf13/cobra"
)

type ExportData struct {
	Version    string          `json:"version"`
	ExportedAt string          `json:"exported_at"`
	Findings   []db.FindingRow `json:"findings"`
	Scans      []db.ScanRow    `json:"scans"`
	Targets    []db.TargetRow  `json:"targets"`
}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export data",
	RunE: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")

		findings, err := db.QueryFindings(db.FindingFilter{Limit: 100000})
		if err != nil {
			return fmt.Errorf("export findings: %w", err)
		}
		scans, err := db.QueryScans(db.ScanFilter{Limit: 100000})
		if err != nil {
			return fmt.Errorf("export scans: %w", err)
		}
		targets, err := db.ListTargets()
		if err != nil {
			return fmt.Errorf("export targets: %w", err)
		}

		data := ExportData{
			Version:    Version,
			ExportedAt: time.Now().Format(time.RFC3339),
			Findings:   findings,
			Scans:      scans,
			Targets:    targets,
		}

		home, _ := os.UserHomeDir()
		outDir := filepath.Join(home, ".fang", "exports")
		os.MkdirAll(outDir, 0755)
		ts := time.Now().Format("2006-01-02_15-04-05")

		switch format {
		case "json":
			body, err := json.MarshalIndent(data, "", "  ")
			if err != nil {
				return err
			}
			path := filepath.Join(outDir, fmt.Sprintf("fang_export_%s.json", ts))
			if err := os.WriteFile(path, body, 0644); err != nil {
				return err
			}
			fmt.Printf("[fang] exported to: %s\n", path)
		case "csv":
			path := filepath.Join(outDir, fmt.Sprintf("fang_export_%s.csv", ts))
			f, err := os.Create(path)
			if err != nil {
				return err
			}
			defer f.Close()
			f.WriteString("Type,ID,Title,Severity,Module,URL,CreatedAt\n")
			for _, fnd := range findings {
				f.WriteString(fmt.Sprintf("finding,%s,%q,%s,%s,%s,%s\n",
					fnd.ID, fnd.Title, fnd.Severity, fnd.ModuleID, fnd.URL.String,
					fnd.CreatedAt.Format(time.RFC3339)))
			}
			fmt.Printf("[fang] exported to: %s\n", path)
		default:
			return fmt.Errorf("unsupported format: %s (use json or csv)", format)
		}
		return nil
	},
}

var importCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import data from file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read import file: %w", err)
		}

		var export ExportData
		if err := json.Unmarshal(data, &export); err != nil {
			return fmt.Errorf("parse import: %w", err)
		}

		imported := 0
		tx, err := db.BeginTx()
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		defer tx.Rollback()

		for _, t := range export.Targets {
			_, err := tx.Exec(
				`INSERT OR IGNORE INTO targets (id, url, domain, name, tags, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				t.ID, t.URL, t.Domain, t.Name, t.Tags, t.CreatedBy, t.CreatedAt,
			)
			if err == nil {
				imported++
			}
		}
		for _, s := range export.Scans {
			_, err := tx.Exec(
				`INSERT OR IGNORE INTO scans (id, target_id, status, modules, threads, timeout, proxy, triggered_by, schedule_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				s.ID, s.TargetID, s.Status, s.Modules, s.Threads, s.Timeout, s.Proxy, s.TriggeredBy, s.ScheduleID, s.CreatedAt,
			)
			if err == nil {
				imported++
			}
		}
		for _, f := range export.Findings {
			_, err := tx.Exec(
				`INSERT OR IGNORE INTO findings (id, scan_id, target_id, module_id, title, severity, confidence, cwe_id, url, parameter, payload, evidence, description, remediation, request, response, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				f.ID, f.ScanID, f.TargetID, f.ModuleID, f.Title, f.Severity, f.Confidence, f.CWEID, f.URL, f.Parameter, f.Payload, f.Evidence, f.Description, f.Remediation, f.Request, f.Response, f.CreatedAt,
			)
			if err == nil {
				imported++
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit import: %w", err)
		}

		fmt.Printf("[fang] imported %d records\n", imported)
		return nil
	},
}

func init() {
	exportCmd.Flags().StringP("format", "f", "json", "export format (json, csv)")

	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(importCmd)
}
