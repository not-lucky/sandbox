package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"cloakid/internal/identity"
	"cloakid/internal/logging"
	"github.com/spf13/cobra"
)

var cloneCmd = &cobra.Command{
	Use:   "clone <src> <dst>",
	Short: "Clone identity state",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		src := args[0]
		dst := args[1]
		logging.AuditLog("Clone requested for: " + src + " -> " + dst)

		srcDir := identity.GetIdentityPath(src)
		dstDir := identity.GetIdentityPath(dst)

		if _, err := os.Stat(srcDir); os.IsNotExist(err) {
			return fmt.Errorf("source identity '%s' does not exist", src)
		}
		if _, err := os.Stat(dstDir); err == nil {
			return fmt.Errorf("target identity '%s' already exists", dst)
		}

		if err := exec.Command("cp", "-r", "--", srcDir, dstDir).Run(); err != nil {
			return err
		}

		// Remove any stale PID file in the cloned directory
		dstPid := filepath.Join(dstDir, ".cloakid.pid")
		os.Remove(dstPid)

		logging.Info("Cloned %s to %s", src, dst)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(cloneCmd)
}
