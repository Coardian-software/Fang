package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/aydocs/fang/internal/engine"
	"github.com/spf13/cobra"
)

var modulesCmd = &cobra.Command{
	Use:   "modules",
	Short: "List available security modules",
	RunE: func(cmd *cobra.Command, args []string) error {
		modules := engine.GetRegistry().List()

		if flagJSON {
			type modInfo struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Severity    string `json:"severity"`
			}
			list := make([]modInfo, 0, len(modules))
			for _, m := range modules {
				list = append(list, modInfo{
					ID:          m.ID(),
					Name:        m.Name(),
					Description: m.Description(),
					Severity:    m.Severity().String(),
				})
			}
			printJSON(list)
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tSEVERITY\tDESCRIPTION")
		for _, m := range modules {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				m.ID(), m.Name(), m.Severity().String(), truncate(m.Description(), 60))
		}
		w.Flush()
		fmt.Printf("\nTotal: %d modules\n", len(modules))
		return nil
	},
}

var modulesShowCmd = &cobra.Command{
	Use:   "show [module-id]",
	Short: "Show module details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		modules := engine.GetRegistry().List()
		for _, m := range modules {
			if m.ID() == args[0] {
				fmt.Printf("ID:          %s\n", m.ID())
				fmt.Printf("Name:        %s\n", m.Name())
				fmt.Printf("Description: %s\n", m.Description())
				fmt.Printf("Severity:    %s\n", m.Severity().String())
				return nil
			}
		}
		return fmt.Errorf("module not found: %s", args[0])
	},
}

func init() {
	modulesCmd.AddCommand(modulesShowCmd)
	rootCmd.AddCommand(modulesCmd)
}
