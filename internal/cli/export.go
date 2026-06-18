package cli

import (
	"cloakid/internal/identity"
	"cloakid/internal/logging"
	"github.com/spf13/cobra"
	"os/exec"
)

var exportCmd = &cobra.Command{
	Use:   "export <identity>",
	Short: "Export identity state as tarball",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		logging.AuditLog("Export requested for: " + name)

		outFile := name + "-identity.tar.gz"
		c := exec.Command("tar", "-czf", outFile, "-C", identity.GetIdentitiesRoot(), name)
		if err := c.Run(); err != nil {
			return err
		}
		logging.Info("Exported to %s", outFile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)
}
