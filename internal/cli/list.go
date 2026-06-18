package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cloakid/internal/identity"
	"cloakid/internal/logging"
	"github.com/spf13/cobra"
)

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all identities and their size",
	Run: func(cmd *cobra.Command, args []string) {
		root := identity.GetIdentitiesRoot()
		entries, err := os.ReadDir(root)
		if err != nil {
			logging.Info("No identities found.")
			return
		}
		found := false
		for _, entry := range entries {
			if entry.IsDir() {
				name := entry.Name()
				if strings.HasPrefix(name, ".") {
					continue
				}

				dir := identity.GetIdentityPath(name)
				size := "N/A"
				if Verbose {
					homeDir := identity.GetIdentityHome(name)
					if s, err := getDirSize(homeDir); err == nil {
						size = formatSize(s)
					}
				}

				fmt.Printf("  %s  (state: %s, path: %s)\n", name, size, dir)
				found = true
			}
		}
		if !found {
			logging.Info("No identities found.")
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
