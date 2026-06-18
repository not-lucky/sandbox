package cli

import (
	"cloakid/internal/logging"
	"github.com/spf13/cobra"
	"os/exec"
	"strings"
)

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Cleanup stale network interfaces and namespaces",
	Run: func(cmd *cobra.Command, args []string) {
		logging.Info("Cleaning up namespaces...")
		cmdList := exec.Command("ip", "netns", "list")
		out, _ := cmdList.Output()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "ns-") {
				ns := strings.Split(line, " ")[0]
				exec.Command("sudo", "ip", "netns", "delete", ns).Run()
			}
		}

		logging.Info("Cleaning up veth interfaces...")
		cmdLink := exec.Command("ip", "link", "show")
		out, _ = cmdLink.Output()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, ": vh-") {
				parts := strings.Split(line, ": ")
				if len(parts) > 1 {
					veth := strings.Split(parts[1], "@")[0]
					exec.Command("sudo", "ip", "link", "delete", veth).Run()
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(cleanupCmd)
}
