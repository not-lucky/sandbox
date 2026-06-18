package cli

import (
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show config parameters",
	Run: func(cmd *cobra.Command, args []string) {
		if cfg != nil {
			d, _ := yaml.Marshal(cfg)
			fmt.Println(string(d))
		} else {
			fmt.Println("No config loaded")
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
