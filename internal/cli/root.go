package cli

import (
	"fmt"
	"os"

	"cloakid/internal/config"
	"cloakid/internal/logging"
	"cloakid/internal/proxy"
	"github.com/spf13/cobra"
)

var (
	Verbose bool
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "cloakid",
	Short: "Identity-Based Secure Workspace Manager",
}

var dnsProxyCmd = &cobra.Command{
	Use:    "dns-proxy [upstream]",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return proxy.RunDNSProxy(args[0])
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().BoolVar(&Verbose, "verbose", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&logging.AuditEnabled, "audit", false, "enable audit log")
	rootCmd.AddCommand(dnsProxyCmd)
}

func initConfig() {
	var err error
	cfg, err = config.LoadConfig()
	if err != nil {
		fmt.Println("Error loading config:", err)
	}
	if Verbose || (cfg != nil && cfg.Verbose) {
		logging.CurrentLevel = logging.LevelDebug
	}
	logging.InitAuditLog()
}
