package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/aydocs/fang/internal/db"
	"github.com/aydocs/fang/internal/scheduler"
	"github.com/spf13/cobra"
)

var schedCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Manage scan schedules",
}

var schedListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all schedules",
	RunE: func(cmd *cobra.Command, args []string) error {
		schedules, err := db.ListSchedules()
		if err != nil {
			return err
		}

		if flagJSON {
			data, _ := json.MarshalIndent(schedules, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tCRON\tTARGET\tENABLED\tLAST RUN")
		for _, s := range schedules {
			target := ""
			t, err := db.GetTarget(s.TargetID)
			if err == nil {
				target = truncate(t.URL, 40)
			}
			lastRun := ""
			if !s.LastRunAt.IsZero() {
				lastRun = s.LastRunAt.Format("2006-01-02 15:04")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\t%s\n",
				s.ID, s.Name, s.CronExpr, target, s.Enabled, lastRun)
		}
		w.Flush()
		return nil
	},
}

var schedCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new schedule",
	RunE: func(cmd *cobra.Command, args []string) error {
		targetID, _ := cmd.Flags().GetString("target-id")
		name, _ := cmd.Flags().GetString("name")
		cronExpr, _ := cmd.Flags().GetString("cron")
		modules, _ := cmd.Flags().GetString("modules")
		notifyOn, _ := cmd.Flags().GetString("notify")
		webhook, _ := cmd.Flags().GetString("webhook")

		if targetID == "" || cronExpr == "" {
			return fmt.Errorf("--target-id and --cron are required")
		}

		id, err := db.CreateSchedule(targetID, name, cronExpr, modules, notifyOn, webhook, "")
		if err != nil {
			return err
		}

		s := scheduler.New()
		s.Start()
		s.Add(id, cronExpr)

		fmt.Printf("[fang] schedule created: %s\n", id)
		return nil
	},
}

var schedDeleteCmd = &cobra.Command{
	Use:   "delete [schedule-id]",
	Short: "Delete a schedule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := db.DeleteSchedule(args[0]); err != nil {
			return err
		}
		fmt.Printf("[fang] schedule %s deleted\n", args[0])
		return nil
	},
}

func init() {
	schedCreateCmd.Flags().String("target-id", "", "target ID (required)")
	schedCreateCmd.Flags().String("name", "", "schedule name")
	schedCreateCmd.Flags().String("cron", "", "cron expression (required)")
	schedCreateCmd.Flags().String("modules", "", "comma-separated module IDs")
	schedCreateCmd.Flags().String("notify", "critical", "notify on severity")
	schedCreateCmd.Flags().String("webhook", "", "webhook URL")

	schedCmd.AddCommand(schedListCmd)
	schedCmd.AddCommand(schedCreateCmd)
	schedCmd.AddCommand(schedDeleteCmd)

	rootCmd.AddCommand(schedCmd)
}
