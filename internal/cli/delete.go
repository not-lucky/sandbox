package cli

import (
	"fmt"
	"os"
	"strings"

	"cloakid/internal/identity"
	"cloakid/internal/logging"
	"github.com/spf13/cobra"
)

var deleteForce bool

var deleteCmd = &cobra.Command{
	Use:   "delete <identity>",
	Short: "Delete identity state directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		logging.AuditLog("Delete requested for: " + name)

		if !deleteForce {
			fmt.Printf("Permanently delete identity '%s' and all its state? [y/N]: ", name)
			var confirm string
			_, err := fmt.Scanln(&confirm)
			if err != nil || (strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes") {
				logging.Info("Deletion cancelled.")
				return nil
			}
		}

		dir := identity.GetIdentityPath(name)
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		logging.Info("Deleted identity %s", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)
	deleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Force delete without confirmation prompt")
}
