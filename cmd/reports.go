package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aydocs/fang/internal/db"
	"github.com/aydocs/fang/internal/report"
	"github.com/aydocs/fang/pkg/models"
	"github.com/spf13/cobra"
)

var reportsCmd = &cobra.Command{
	Use:   "report",
	Short: "Report generation",
}

var reportGenerateCmd = &cobra.Command{
	Use:   "generate [scan-id]",
	Short: "Generate a report for a scan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID := args[0]
		format, _ := cmd.Flags().GetString("format")

		scan, err := db.GetScan(scanID)
		if err != nil {
			return fmt.Errorf("scan not found: %w", err)
		}

		findings, err := db.QueryFindings(db.FindingFilter{ScanID: scanID, Limit: 10000})
		if err != nil {
			return fmt.Errorf("query findings: %w", err)
		}

		target, err := db.GetTarget(scan.TargetID)
		if err != nil {
			return fmt.Errorf("target not found: %w", err)
		}

		result := &models.ScanResult{
			Target:   target.URL,
			Findings: make([]*models.Finding, len(findings)),
		}

		for i, f := range findings {
			result.Findings[i] = &models.Finding{
				ModuleID:      f.ModuleID,
				Title:         f.Title,
				URL:           f.URL.String,
				Evidence:      f.Evidence.String,
				Severity:      parseSeverity(f.Severity),
				Confidence:    parseConfidence(f.Confidence),
				CWEID:         f.CWEID.String,
				OWASPCategory: f.OWASPCategory.String,
				CVSS: func() *float64 {
					if f.CVSS.Valid {
						v := f.CVSS.Float64
						return &v
					}
					return nil
				}(),
				Parameter:   f.Parameter.String,
				Payload:     f.Payload.String,
				Description: f.Description.String,
				Remediation: f.Remediation.String,
				Request:     f.Request.String,
				Response:    f.Response.String,
				CheckID:     f.CheckID,
				Fingerprint: f.Fingerprint.String,
				Status:      f.Status,
				Occurrences: f.Occurrences,
			}
		}

		eng := report.New(&report.Config{
			OutputDir:       filepath.Join(os.Getenv("HOME"), ".fang", "reports"),
			Formats:         []string{format},
			IncludeEvidence: true,
		})

		paths, err := eng.Generate(context.Background(), result)
		if err != nil {
			return fmt.Errorf("generate report: %w", err)
		}

		if len(paths) > 0 {
			fmt.Printf("[fang] report generated: %s\n", paths[0])
			return nil
		}
		return fmt.Errorf("no report generated")
	},
}

var reportListCmd = &cobra.Command{
	Use:   "list",
	Short: "List generated reports",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, _ := os.UserHomeDir()
		reportDir := filepath.Join(home, ".fang", "reports")

		entries, err := os.ReadDir(reportDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("[fang] no reports found")
				return nil
			}
			return err
		}

		if flagJSON {
			type reportInfo struct {
				Name string `json:"name"`
				Size int64  `json:"size"`
				Time string `json:"time"`
			}
			var list []reportInfo
			for _, e := range entries {
				info, _ := e.Info()
				list = append(list, reportInfo{
					Name: e.Name(),
					Size: info.Size(),
					Time: info.ModTime().Format(time.RFC3339),
				})
			}
			data, _ := json.MarshalIndent(list, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		for _, e := range entries {
			info, _ := e.Info()
			fmt.Printf("%s  %d bytes  %s\n",
				e.Name(), info.Size(), info.ModTime().Format("2006-01-02 15:04"))
		}
		return nil
	},
}

func init() {
	reportGenerateCmd.Flags().StringP("format", "f", "html", "report format (json, sarif, markdown, html, pdf)")

	reportsCmd.AddCommand(reportGenerateCmd)
	reportsCmd.AddCommand(reportListCmd)

	rootCmd.AddCommand(reportsCmd)
}

func parseSeverity(s string) models.Severity {
	switch s {
	case "CRITICAL":
		return models.Critical
	case "HIGH":
		return models.High
	case "MEDIUM":
		return models.Medium
	case "LOW":
		return models.Low
	default:
		return models.Info
	}
}

func parseConfidence(s string) models.Confidence {
	switch s {
	case "CRITICAL":
		return models.CriticalConfidence
	case "HIGH":
		return models.HighConfidence
	case "MEDIUM":
		return models.MediumConfidence
	case "LOW":
		return models.LowConfidence
	default:
		return models.Tentative
	}
}
