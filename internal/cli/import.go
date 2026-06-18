package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"cloakid/internal/identity"
	"cloakid/internal/logging"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import <archive> [new_name]",
	Short: "Import identity state from tarball",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		archive := args[0]
		logging.AuditLog("Import requested for: " + archive)

		c := exec.Command("tar", "-tzf", archive)
		out, err := c.Output()
		if err != nil {
			return err
		}
		lines := strings.Split(string(out), "\n")
		if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
			return fmt.Errorf("empty or invalid archive")
		}
		origName := strings.Split(lines[0], "/")[0]

		targetName := origName
		if len(args) == 2 {
			targetName = identity.Sanitize(args[1])
		}

		targetDir := identity.GetIdentityPath(targetName)
		if _, err := os.Stat(targetDir); err == nil {
			return fmt.Errorf("target identity '%s' already exists", targetName)
		}

		tempDir := filepath.Join(identity.GetIdentitiesRoot(), ".import_temp")
		os.RemoveAll(tempDir)
		os.MkdirAll(tempDir, 0755)

		if err := exec.Command("tar", "-xzf", archive, "-C", tempDir).Run(); err != nil {
			os.RemoveAll(tempDir)
			return err
		}

		if targetName != origName {
			if err := os.Rename(filepath.Join(tempDir, origName), filepath.Join(tempDir, targetName)); err != nil {
				os.RemoveAll(tempDir)
				return fmt.Errorf("failed to rename extracted directory: %w", err)
			}
		}

		if err := os.Rename(filepath.Join(tempDir, targetName), targetDir); err != nil {
			os.RemoveAll(tempDir)
			return fmt.Errorf("failed to move imported directory: %w", err)
		}

		os.RemoveAll(tempDir)
		logging.Info("Imported identity %s", targetName)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(importCmd)
}
