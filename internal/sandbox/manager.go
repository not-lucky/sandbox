package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cloakid/internal/identity"
	"cloakid/internal/logging"
	"cloakid/internal/netns"
	"cloakid/internal/proxy"
)

type Manager struct {
	Identity  string
	SocksPort int
	DNS       string
	Timeout   int
	NoSandbox bool
	NoProxy   bool
	Profile   string
	Whitelist string
	DryRun    bool

	// ForwardMappings is the explicit list of host->namespace port mappings
	// (from --forward). When non-empty and ForwardAll is false, each mapping
	// gets a dedicated socat forwarder at sandbox startup.
	ForwardMappings []proxy.PortMapping

	// ForwardAll enables the AutoForwarder goroutine which mirrors every
	// TCP port the namespace apps start listening on to the host loopback.
	// Mutually exclusive with ForwardMappings.
	ForwardAll bool

	// Quiet silences the inner command's stdout/stderr by routing them to
	// a timestamped log file under /tmp. CloakID's own logging output is
	// unaffected. Stdin stays attached so interactive prompts still work.
	Quiet bool
}

func checkPortConflict(proxyIP string, port int) error {
	cmd := exec.Command("ss", "-tln")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddr := fields[3]
		portStr := fmt.Sprintf(":%d", port)
		if strings.HasSuffix(localAddr, portStr) {
			host := strings.TrimSuffix(localAddr, portStr)
			host = strings.Trim(host, "[]")
			if host == "0.0.0.0" || host == "::" || host == "*" || host == "" || host == proxyIP {
				return fmt.Errorf("port %d is already in use on local address %s", port, localAddr)
			}
		}
	}
	return nil
}

func (m *Manager) acquireLock(hwCfg netns.HardwareConfig) (*os.File, error) {
	identityDir := identity.GetIdentityPath(m.Identity)
	lockFilePath := filepath.Join(identityDir, ".lock")
	lockFile, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}

	err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		pidFile := identity.GetPIDFile(m.Identity)
		if pidBytes, rErr := os.ReadFile(pidFile); rErr == nil {
			if pid, pErr := strconv.Atoi(strings.TrimSpace(string(pidBytes))); pErr == nil {
				if identity.IsSandboxPID(pid) {
					lockFile.Close()
					return nil, fmt.Errorf("another sandbox instance for identity '%s' is already running", m.Identity)
				}
			}
		}
		logging.Warn("Found stale lock for identity '%s'. Recovering...", m.Identity)
		netns.TeardownNetwork(hwCfg)

		err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err != nil {
			lockFile.Close()
			return nil, fmt.Errorf("another sandbox instance for identity '%s' is already running (failed lock retry)", m.Identity)
		}
	}
	return lockFile, nil
}

func (m *Manager) printDryRunTopology(hwCfg netns.HardwareConfig, profContent, cwd, fakeHome string) {
	fmt.Println("=== DRY RUN MODE: No system-altering commands will be executed ===")
	fmt.Println("Proposed Namespace Topology:")
	fmt.Printf("  Namespace Name:      %s\n", hwCfg.NSName)
	fmt.Printf("  Veth Host Interface: %s (IP: %s/24)\n", hwCfg.VethHost, hwCfg.ProxyIP)
	fmt.Printf("  Veth NS Interface:   %s (IP: %s/24, Spoofed MAC: %s)\n", hwCfg.VethNS, hwCfg.NSIP, hwCfg.MACAddr)
	fmt.Println("  Tunnel Interface:    tun0 (Route: default)")
	fmt.Printf("  Upstream Proxy:      socks5://%s:%d\n", hwCfg.ProxyIP, hwCfg.SocksPort)
	fmt.Printf("  Upstream DNS:        %s\n", m.DNS)
	fmt.Printf("  State Home Directory: %s\n", fakeHome)
	fmt.Println("  Machine ID:          Spoofed (Random)")
	if m.Timeout > 0 {
		fmt.Printf("  Timeout:             %ds\n", m.Timeout)
	}
	fmt.Println("Proposed Firejail Profile:")
	fmt.Println("--------------------------------------------------------")
	fmt.Print(profContent)
	fmt.Println("--------------------------------------------------------")
	fmt.Println("Proposed Whitelist Mounts:")
	fmt.Printf("  Identity root: %s\n", identity.GetIdentityPath(m.Identity))
	fmt.Printf("  Working dir:   %s\n", cwd)
	if m.Whitelist != "" {
		for _, w := range strings.Split(m.Whitelist, ",") {
			fmt.Printf("  User whitelist: %s\n", w)
		}
	}
	fmt.Println("Proposed Port Forwarding:")
	if m.ForwardAll {
		fmt.Println("  Mode: all TCP ports the namespace apps listen on (mirrored to host 127.0.0.1)")
	} else if len(m.ForwardMappings) > 0 {
		for _, pm := range m.ForwardMappings {
			fmt.Printf("  host 127.0.0.1:%d -> namespace 127.0.0.1:%d\n", pm.HostPort, pm.NSPort)
		}
	} else {
		fmt.Println("  (none)")
	}
	if m.Quiet {
		fmt.Println("Quiet: child stdout/stderr -> /tmp/cloakid-quiet-<identity>-<timestamp>.log")
	}
}

func (m *Manager) setupSignalHandler(cancelProcess context.CancelFunc, hwCfg netns.HardwareConfig) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigs:
			logging.Info("Interrupted. Cleaning up network and processes...")
			cancelProcess()
			netns.TeardownNetwork(hwCfg)
			os.Exit(1)
		}
	}()
}

func (m *Manager) startProxies(ctx context.Context, hwCfg netns.HardwareConfig) error {
	_, err := proxy.StartSocat(ctx, hwCfg.ProxyIP, hwCfg.SocksPort)
	if err != nil {
		return fmt.Errorf("failed to start socat: %w", err)
	}

	_, err = proxy.StartTun2Socks(ctx, hwCfg.NSName, hwCfg.ProxyIP, hwCfg.SocksPort)
	if err != nil {
		return fmt.Errorf("failed to start tun2socks: %w", err)
	}

	exePath, _ := os.Executable()
	dnsCmd := exec.CommandContext(ctx, "sudo", "ip", "netns", "exec", hwCfg.NSName, exePath, "dns-proxy", m.DNS)
	if logFile, err := os.OpenFile("/tmp/cloakid-dns.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666); err == nil {
		dnsCmd.Stdout = logFile
		dnsCmd.Stderr = logFile
		defer logFile.Close()
	}
	if err := dnsCmd.Start(); err != nil {
		return fmt.Errorf("failed to start dns proxy: %w", err)
	}

	time.Sleep(100 * time.Millisecond)
	if err := dnsCmd.Process.Signal(syscall.Signal(0)); err != nil {
		logContent, _ := os.ReadFile("/tmp/cloakid-dns.log")
		return fmt.Errorf("dns proxy exited prematurely: %w (log: %s)", err, string(logContent))
	}
	return nil
}

// startForwarders wires port forwarding based on the Manager configuration.
// Either ForwardMappings (explicit list) or ForwardAll (auto-discover every
// TCP port the namespace apps listen on) is honoured, never both.
func (m *Manager) startForwarders(ctx context.Context, hwCfg netns.HardwareConfig) error {
	if m.ForwardAll {
		if len(m.ForwardMappings) > 0 {
			return fmt.Errorf("internal error: ForwardAll and ForwardMappings are mutually exclusive")
		}
		af := proxy.NewAutoForwarder(ctx, hwCfg.NSName, hwCfg.SocksPort)
		af.Start()
		logging.Info("AutoForwarder enabled: every TCP port the namespace apps listen on will be mirrored to host 127.0.0.1")
		return nil
	}

	if len(m.ForwardMappings) == 0 {
		return nil
	}

	// Forwarders are spawned with exec.CommandContext(ctx, …) inside
	// proxy.StartPortForwarding, so processCtx cancellation on shutdown
	// tears them down cleanly. No additional tracking or kill is needed here.
	for _, pm := range m.ForwardMappings {
		if err := checkPortConflict("127.0.0.1", pm.HostPort); err != nil {
			return fmt.Errorf("cannot forward host port %d: %w", pm.HostPort, err)
		}
		if _, err := proxy.StartPortForwarding(ctx, hwCfg.NSName, pm.HostPort, pm.NSPort); err != nil {
			return fmt.Errorf("failed to start forwarder for host:%d -> ns:%d: %w", pm.HostPort, pm.NSPort, err)
		}
	}
	return nil
}

func (m *Manager) buildWhitelist(fakeHome, realHome, cwd, cmdPath string) []string {
	var whitelistArgs []string
	addWhitelistMount := func(hostPath string) {
		if _, err := os.Stat(hostPath); os.IsNotExist(err) {
			return
		}
		whitelistArgs = append(whitelistArgs, "--whitelist="+hostPath)
		if strings.HasPrefix(hostPath, realHome) {
			relPath, err := filepath.Rel(realHome, hostPath)
			if err == nil {
				fakePath := filepath.Join(fakeHome, relPath)
				if fakePath != fakeHome {
					os.MkdirAll(filepath.Dir(fakePath), 0755)
					os.Symlink(hostPath, fakePath)
				}
			}
		}
	}

	whitelistArgs = append(whitelistArgs, "--whitelist="+identity.GetIdentitiesRoot())
	addWhitelistMount(cwd)

	if filepath.IsAbs(cmdPath) && strings.HasPrefix(cmdPath, realHome) {
		addWhitelistMount(cmdPath)
	}

	if m.Whitelist != "" {
		for _, w := range strings.Split(m.Whitelist, ",") {
			if strings.HasPrefix(w, "~/") {
				w = filepath.Join(realHome, w[2:])
			} else if w == "~" {
				w = realHome
			} else {
				if absW, err := filepath.Abs(w); err == nil {
					w = absW
				}
			}
			addWhitelistMount(w)
		}
	}
	return whitelistArgs
}

func (m *Manager) Run(ctx context.Context, args []string) error {
	identity.EnsureDirs(m.Identity)
	hwCfg := netns.GenerateHardwareConfig(m.Identity, m.SocksPort)

	if !m.DryRun && !m.NoProxy {
		if err := checkPortConflict(hwCfg.ProxyIP, m.SocksPort); err != nil {
			return err
		}
	}

	if !m.DryRun {
		lockFile, err := m.acquireLock(hwCfg)
		if err != nil {
			return err
		}
		defer func() {
			syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			lockFile.Close()
		}()
	}

	profName := ResolveProfile(args[0], m.Profile)
	cmdBase := filepath.Base(args[0])
	profContent := BuildProfileContent(m.Identity, profName, cmdBase, m.NoProxy)
	profPath := filepath.Join(identity.GetIdentityConfigs(m.Identity), "sandbox.profile")

	realHome, _ := os.UserHomeDir()
	fakeHome := identity.GetIdentityHome(m.Identity)
	cwd, _ := os.Getwd()

	if m.DryRun {
		m.printDryRunTopology(hwCfg, profContent, cwd, fakeHome)
		return nil
	}

	WriteProfile(profPath, profContent)

	if !m.NoProxy {
		logging.Info("Setting up network for identity: %s", m.Identity)
		if err := netns.SetupNetwork(hwCfg); err != nil {
			return fmt.Errorf("network setup failed: %w", err)
		}

		defer func() {
			logging.Info("Cleaning up network for identity: %s", m.Identity)
			netns.TeardownNetwork(hwCfg)
		}()
	}

	processCtx, cancelProcess := context.WithCancel(ctx)
	defer cancelProcess()

	if !m.NoProxy {
		m.setupSignalHandler(cancelProcess, hwCfg)

		if err := m.startProxies(processCtx, hwCfg); err != nil {
			return err
		}

		if err := m.startForwarders(processCtx, hwCfg); err != nil {
			return err
		}
	}

	cmdPath, _ := exec.LookPath(args[0])
	if cmdPath == "" {
		cmdPath = args[0]
	}

	whitelistArgs := m.buildWhitelist(fakeHome, realHome, cwd, cmdPath)

	opts := ExecuteOptions{
		NSName:       hwCfg.NSName,
		Identity:     m.Identity,
		HomeDir:      fakeHome,
		NoSandbox:    m.NoSandbox,
		NoProxy:      m.NoProxy,
		Timeout:      m.Timeout,
		CommandArgs:  args,
		ProfilePath:  profPath,
		Whitelist:    whitelistArgs,
		IdentityRoot: identity.GetIdentityPath(m.Identity),
		Cwd:          cwd,
		Quiet:        m.Quiet,
	}

	err := Execute(opts)
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}
	return nil
}
