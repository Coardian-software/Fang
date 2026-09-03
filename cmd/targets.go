package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/aydocs/fang/internal/db"
	"github.com/spf13/cobra"
)

var targetsCmd = &cobra.Command{
	Use:   "targets",
	Short: "Manage scan targets",
}

var targetsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all targets",
	RunE: func(cmd *cobra.Command, args []string) error {
		targets, err := db.ListTargets()
		if err != nil {
			return err
		}

		if flagJSON {
			data, _ := json.MarshalIndent(targets, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tURL\tDOMAIN\tNAME\tCREATED")
		for _, t := range targets {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				t.ID, truncate(t.URL, 50), t.Domain, t.Name,
				t.CreatedAt.Format("2006-01-02"))
		}
		w.Flush()
		return nil
	},
}

var targetsAddCmd = &cobra.Command{
	Use:   "add [url]",
	Short: "Add a new target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		domain, _ := cmd.Flags().GetString("domain")
		tags, _ := cmd.Flags().GetString("tags")

		id, err := db.CreateTarget(args[0], domain, name, tags, "")
		if err != nil {
			return err
		}
		fmt.Printf("[fang] target created: %s\n", id)
		return nil
	},
}

var targetsDeleteCmd = &cobra.Command{
	Use:   "delete [target-id]",
	Short: "Delete a target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := db.DeleteTarget(args[0]); err != nil {
			return err
		}
		fmt.Printf("[fang] target %s deleted\n", args[0])
		return nil
	},
}

var targetsShowCmd = &cobra.Command{
	Use:   "show [target-id]",
	Short: "Show target details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		t, err := db.GetTarget(args[0])
		if err != nil {
			return err
		}

		if flagJSON {
			data, _ := json.MarshalIndent(t, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("ID:      %s\n", t.ID)
		fmt.Printf("URL:     %s\n", t.URL)
		fmt.Printf("Domain:  %s\n", t.Domain)
		fmt.Printf("Name:    %s\n", t.Name)
		fmt.Printf("Tags:    %s\n", t.Tags)
		fmt.Printf("Created: %s\n", t.CreatedAt.Format("2006-01-02 15:04"))
		return nil
	},
}

func init() {
	targetsAddCmd.Flags().String("name", "", "target name")
	targetsAddCmd.Flags().String("domain", "", "target domain")
	targetsAddCmd.Flags().String("tags", "", "comma-separated tags")

	targetsCmd.AddCommand(targetsListCmd)
	targetsCmd.AddCommand(targetsAddCmd)
	targetsCmd.AddCommand(targetsDeleteCmd)
	targetsCmd.AddCommand(targetsShowCmd)

	rootCmd.AddCommand(targetsCmd)
}
