package cli

import (
	"context"
	"fmt"

	"cloakid/internal/logging"
	"cloakid/internal/sandbox"
	"github.com/spf13/cobra"
)

var (
	runIdentity  string
	runWhitelist string
	runSocksPort int
	runProfile   string
	runDNS       string
	runTimeout   int
	runNoSandbox bool
	runDryRun    bool
)

var runCmd = &cobra.Command{
	Use:   "run [options] -- <command> [args...]",
	Short: "Launch a command inside CloakID",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logging.AuditLog(fmt.Sprintf("Run requested for identity: %s", runIdentity))
		if runIdentity == "" {
			if cfg != nil {
				runIdentity = cfg.DefaultIdentity
			}
		}
		if runIdentity == "" {
			return fmt.Errorf("identity is required")
		}

		if runSocksPort == 0 && cfg != nil {
			runSocksPort = cfg.DefaultSOCKSPort
		}
		if runDNS == "" && cfg != nil {
			runDNS = cfg.DefaultDNS
		}
		if runTimeout == 0 && cfg != nil {
			runTimeout = cfg.DefaultTimeout
		}

		noSandbox := runNoSandbox
		if cfg != nil && cfg.NoSandbox {
			noSandbox = true
		}

		manager := &sandbox.Manager{
			Identity:  runIdentity,
			SocksPort: runSocksPort,
			DNS:       runDNS,
			Timeout:   runTimeout,
			NoSandbox: noSandbox,
			Profile:   runProfile,
			Whitelist: runWhitelist,
			DryRun:    runDryRun,
		}

		ctx := context.Background()
		return manager.Run(ctx, args)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&runIdentity, "identity", "i", "", "Identity name")
	runCmd.Flags().StringVarP(&runWhitelist, "whitelist", "w", "", "Comma-separated whitelist")
	runCmd.Flags().IntVarP(&runSocksPort, "port", "p", 0, "SOCKS5 proxy port")
	runCmd.Flags().StringVarP(&runProfile, "profile", "f", "", "Firejail profile")
	runCmd.Flags().StringVarP(&runDNS, "dns", "d", "", "DNS server")
	runCmd.Flags().IntVarP(&runTimeout, "timeout", "t", 0, "Timeout in seconds")
	runCmd.Flags().BoolVarP(&runNoSandbox, "no-sandbox", "n", false, "Disable firejail")
	runCmd.Flags().BoolVar(&runDryRun, "dry-run", false, "Dry run mode")
}
