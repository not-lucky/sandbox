package cli

import (
	"context"
	"fmt"

	"cloakid/internal/logging"
	"cloakid/internal/proxy"
	"cloakid/internal/sandbox"
	"github.com/spf13/cobra"
)

var (
	runIdentity   string
	runWhitelist  string
	runSocksPort  int
	runProfile    string
	runDNS        string
	runTimeout    int
	runNoSandbox  bool
	runNoProxy    bool
	runDryRun     bool
	runForward    string
	runForwardAll bool
	runQuiet      bool
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

		noProxy := runNoProxy
		if cfg != nil && cfg.NoProxy {
			noProxy = true
		}

		mappings, err := resolveForwardMappings(runForward, runForwardAll)
		if err != nil {
			return err
		}

		manager := &sandbox.Manager{
			Identity:        runIdentity,
			SocksPort:       runSocksPort,
			DNS:             runDNS,
			Timeout:         runTimeout,
			NoSandbox:       noSandbox,
			NoProxy:         noProxy,
			Profile:         runProfile,
			Whitelist:       runWhitelist,
			DryRun:          runDryRun,
			ForwardMappings: mappings,
			ForwardAll:      runForwardAll,
			Quiet:           runQuiet,
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
	runCmd.Flags().BoolVar(&runNoProxy, "no-proxy", false, "Disable network namespace and SOCKS proxy (run directly on host network)")
	runCmd.Flags().BoolVar(&runDryRun, "dry-run", false, "Dry run mode")
	runCmd.Flags().StringVar(&runForward, "forward", "", "Comma-separated host:namespace port mappings (e.g. 8080:80,9090:9090). A bare port like '38085' forwards host:38085 -> namespace:38085.")
	runCmd.Flags().BoolVar(&runForwardAll, "forward-all", false, "Auto-forward every TCP port the namespace apps listen on")
	runCmd.Flags().BoolVarP(&runQuiet, "quiet", "q", false, "Silence the inner command; tee its output to /tmp/cloakid-quiet-<identity>-<timestamp>.log")
}

// resolveForwardMappings validates the --forward / --forward-all combination
// and parses the mapping string. Both flags set is a configuration error;
// either alone is valid (empty forward with forwardAll unset is also valid).
func resolveForwardMappings(forward string, forwardAll bool) ([]proxy.PortMapping, error) {
	if forward != "" && forwardAll {
		return nil, fmt.Errorf("--forward and --forward-all are mutually exclusive")
	}
	return proxy.ParsePortMappings(forward)
}
