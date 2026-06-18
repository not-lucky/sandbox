package cli

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"cloakid/internal/identity"
	"cloakid/internal/logging"
	"cloakid/internal/netns"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop <identity>",
	Short: "Stop a running sandbox instance",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		logging.AuditLog("Stop requested for: " + name)

		pidFile := identity.GetPIDFile(name)
		pidBytes, err := os.ReadFile(pidFile)
		if err == nil {
			pidStr := strings.TrimSpace(string(pidBytes))
			if pid, pErr := strconv.Atoi(pidStr); pErr == nil {
				if identity.IsSandboxPID(pid) {
					// Kill parent and child processes
					exec.Command("pkill", "--parent", pidStr).Run()
					exec.Command("kill", "-TERM", pidStr).Run()
					time.Sleep(time.Second)
					exec.Command("kill", "-KILL", pidStr).Run()
				} else {
					logging.Warn("PID %d is dead or not a sandbox process. Cleaning stale PID file.", pid)
				}
			}
			os.Remove(pidFile)
		}

		hwCfg := netns.GenerateHardwareConfig(name, 0)
		netns.TeardownNetwork(hwCfg)
		logging.Info("Stopped identity %s", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
