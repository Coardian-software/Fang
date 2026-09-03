package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/aydocs/fang/internal/db"
	"github.com/spf13/cobra"
)

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Manage findings",
}

var findingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		severity, _ := cmd.Flags().GetString("severity")
		scanID, _ := cmd.Flags().GetString("scan-id")
		moduleID, _ := cmd.Flags().GetString("module")

		filter := db.FindingFilter{
			Limit:    limit,
			Offset:   offset,
			Severity: severity,
			ScanID:   scanID,
			ModuleID: moduleID,
		}

		findings, err := db.QueryFindings(filter)
		if err != nil {
			return err
		}

		if flagJSON {
			data, _ := json.MarshalIndent(findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSEVERITY\tMODULE\tTITLE\tURL")
		for _, f := range findings {
			url := ""
			if f.URL.Valid {
				url = f.URL.String
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				f.ID, f.Severity, f.ModuleID, truncate(f.Title, 50), truncate(url, 60))
		}
		w.Flush()
		fmt.Printf("\nTotal: %d findings\n", len(findings))
		return nil
	},
}

var findingsShowCmd = &cobra.Command{
	Use:   "show [finding-id]",
	Short: "Show finding details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := db.GetFinding(args[0])
		if err != nil {
			return err
		}

		if flagJSON {
			data, _ := json.MarshalIndent(f, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("Finding ID:   %s\n", f.ID)
		fmt.Printf("Module:       %s\n", f.ModuleID)
		fmt.Printf("Title:        %s\n", f.Title)
		fmt.Printf("Severity:     %s\n", f.Severity)
		fmt.Printf("Confidence:   %s\n", f.Confidence)
		if f.CWEID.Valid {
			fmt.Printf("CWE:          %s\n", f.CWEID.String)
		}
		if f.URL.Valid {
			fmt.Printf("URL:          %s\n", f.URL.String)
		}
		if f.Parameter.Valid {
			fmt.Printf("Parameter:    %s\n", f.Parameter.String)
		}
		if f.Payload.Valid {
			fmt.Printf("Payload:      %s\n", f.Payload.String)
		}
		if f.Evidence.Valid {
			fmt.Printf("Evidence:     %s\n", f.Evidence.String)
		}
		if f.Description.Valid {
			fmt.Printf("Description:  %s\n", f.Description.String)
		}
		if f.Remediation.Valid {
			fmt.Printf("Remediation:  %s\n", f.Remediation.String)
		}
		fmt.Printf("False Pos:    %v\n", f.IsFalsePositive)
		fmt.Printf("Created:      %s\n", f.CreatedAt.Format("2006-01-02 15:04:05"))
		return nil
	},
}

var findingsUpdateCmd = &cobra.Command{
	Use:   "update [finding-id]",
	Short: "Update a finding",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		falsePos, _ := cmd.Flags().GetBool("false-positive")
		severity, _ := cmd.Flags().GetString("severity")
		notes, _ := cmd.Flags().GetString("notes")

		if err := db.UpdateFinding(args[0], falsePos, severity, notes); err != nil {
			return err
		}
		fmt.Printf("[fang] finding %s updated\n", args[0])
		return nil
	},
}

var findingsStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show findings statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		stats, err := db.GetSeverityBreakdown()
		if err != nil {
			return err
		}

		if flagJSON {
			data, _ := json.MarshalIndent(stats, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SEVERITY\tCOUNT")
		total := 0
		for _, s := range stats {
			fmt.Fprintf(w, "%s\t%d\n", s.Severity, s.Count)
			total += s.Count
		}
		w.Flush()
		fmt.Printf("\nTotal: %d\n", total)
		return nil
	},
}

var findingsDeleteCmd = &cobra.Command{
	Use:   "delete [finding-id]",
	Short: "Delete a finding",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		d := db.DB()
		if d == nil {
			return fmt.Errorf("database not initialized")
		}
		_, err := d.Exec("DELETE FROM findings WHERE id = ?", args[0])
		if err != nil {
			return err
		}
		fmt.Printf("[fang] finding %s deleted\n", args[0])
		return nil
	},
}

func init() {
	findingsListCmd.Flags().IntP("limit", "l", 50, "max findings to show")
	findingsListCmd.Flags().IntP("offset", "O", 0, "offset for pagination")
	findingsListCmd.Flags().StringP("severity", "s", "", "filter by severity")
	findingsListCmd.Flags().String("scan-id", "", "filter by scan ID")
	findingsListCmd.Flags().String("module", "", "filter by module ID")

	findingsUpdateCmd.Flags().Bool("false-positive", false, "mark as false positive")
	findingsUpdateCmd.Flags().String("severity", "", "change severity")
	findingsUpdateCmd.Flags().String("notes", "", "add notes")

	findingsCmd.AddCommand(findingsListCmd)
	findingsCmd.AddCommand(findingsShowCmd)
	findingsCmd.AddCommand(findingsUpdateCmd)
	findingsCmd.AddCommand(findingsStatsCmd)
	findingsCmd.AddCommand(findingsDeleteCmd)

	rootCmd.AddCommand(findingsCmd)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
