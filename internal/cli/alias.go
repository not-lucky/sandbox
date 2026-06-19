package cli

import (
	"fmt"
	"strings"

	"cloakid/internal/config"
	"cloakid/internal/logging"
	"github.com/spf13/cobra"
)

var aliasCmd = &cobra.Command{
	Use:   "alias",
	Short: "Manage command aliases / shortcuts",
}

var aliasAddCmd = &cobra.Command{
	Use:                "add <name> <command_args...>",
	Short:              "Save an alias for a command",
	Args:               cobra.MinimumNArgs(2),
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		aliasArgs := args[1:]

		if cfg == nil {
			var err error
			cfg, err = config.LoadConfig()
			if err != nil {
				return err
			}
		}

		cfg.Aliases[name] = aliasArgs
		if err := config.SaveConfig(cfg); err != nil {
			return fmt.Errorf("failed to save alias: %w", err)
		}

		logging.Info("Saved alias '%s': %s", name, strings.Join(aliasArgs, " "))
		return nil
	},
}

var aliasRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a command alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		if cfg == nil {
			var err error
			cfg, err = config.LoadConfig()
			if err != nil {
				return err
			}
		}

		if _, exists := cfg.Aliases[name]; !exists {
			return fmt.Errorf("alias '%s' does not exist", name)
		}

		delete(cfg.Aliases, name)
		if err := config.SaveConfig(cfg); err != nil {
			return fmt.Errorf("failed to remove alias: %w", err)
		}

		logging.Info("Removed alias '%s'", name)
		return nil
	},
}

var aliasListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all command aliases",
	RunE: func(cmd *cobra.Command, args []string) error {
		if cfg == nil {
			var err error
			cfg, err = config.LoadConfig()
			if err != nil {
				return err
			}
		}

		if len(cfg.Aliases) == 0 {
			logging.Info("No aliases configured.")
			return nil
		}

		fmt.Println("Configured Aliases:")
		for name, aliasArgs := range cfg.Aliases {
			fmt.Printf("  %s -> %s\n", name, strings.Join(aliasArgs, " "))
		}
		return nil
	},
}

func init() {
	aliasCmd.AddCommand(aliasAddCmd)
	aliasCmd.AddCommand(aliasRemoveCmd)
	aliasCmd.AddCommand(aliasListCmd)
	rootCmd.AddCommand(aliasCmd)
}
