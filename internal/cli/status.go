package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"cloakid/internal/identity"
	"cloakid/internal/logging"
	"cloakid/internal/netns"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show running and stopped sandbox instances",
	Run: func(cmd *cobra.Command, args []string) {
		root := identity.GetIdentitiesRoot()
		entries, err := os.ReadDir(root)
		if err != nil {
			logging.Info("No identities found.")
			return
		}

		nsList, _ := netns.ListNamespaces()
		nsMap := make(map[string]bool)
		for _, ns := range nsList {
			nsMap[ns] = true
		}

		found := false
		for _, entry := range entries {
			if entry.IsDir() {
				name := entry.Name()
				if strings.HasPrefix(name, ".") {
					continue
				}
				nsName := "ns-" + identity.Hash(name)
				status := "stopped"

				if nsMap[nsName] {
					status = "namespace active"
					pidFile := identity.GetPIDFile(name)
					if pidBytes, err := os.ReadFile(pidFile); err == nil {
						if pid, pErr := strconv.Atoi(strings.TrimSpace(string(pidBytes))); pErr == nil {
							if identity.IsSandboxPID(pid) {
								status = fmt.Sprintf("running (PID: %d)", pid)

								// Get CPU/Memory usage
								psCmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "%cpu,%mem", "--no-headers")
								if psOut, psErr := psCmd.Output(); psErr == nil {
									fields := strings.Fields(string(psOut))
									if len(fields) >= 2 {
										status += fmt.Sprintf("  CPU: %s%%  MEM: %s%%", fields[0], fields[1])
									}
								}

								// Get network activity if verbose
								if Verbose {
									vethHost := "vh-" + identity.Hash(name)
									rxPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", vethHost)
									txPath := fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", vethHost)
									rxBytes, err1 := os.ReadFile(rxPath)
									txBytes, err2 := os.ReadFile(txPath)
									if err1 == nil && err2 == nil {
										rxVal, _ := strconv.ParseUint(strings.TrimSpace(string(rxBytes)), 10, 64)
										txVal, _ := strconv.ParseUint(strings.TrimSpace(string(txBytes)), 10, 64)
										status += fmt.Sprintf("  RX: %.1f KB, TX: %.1f KB", float64(rxVal)/1024.0, float64(txVal)/1024.0)
									}
								}
							} else {
								status = "namespace active (stale PID)"
							}
						}
					}
				}
				fmt.Printf("  %s  [%s]  ns=%s\n", name, status, nsName)
				found = true
			}
		}
		if !found {
			logging.Info("No identities found.")
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
