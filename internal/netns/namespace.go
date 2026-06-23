package netns

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"cloakid/internal/logging"
)

func runSudo(args ...string) error {
	cmd := exec.Command("sudo", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo %s failed: %w (%s)", strings.Join(args, " "), err, stderr.String())
	}
	return nil
}

func SetupNetwork(cfg HardwareConfig) error {
	logging.Debug("Setting up network for %s", cfg.NSName)

	runSudo("ip", "netns", "delete", cfg.NSName)
	runSudo("ip", "link", "delete", cfg.VethHost)

	if err := runSudo("ip", "netns", "add", cfg.NSName); err != nil {
		return err
	}

	if err := runSudo("ip", "link", "add", cfg.VethHost, "type", "veth", "peer", "name", cfg.VethNS); err != nil {
		return err
	}

	if err := runSudo("ip", "link", "set", cfg.VethNS, "netns", cfg.NSName); err != nil {
		return err
	}

	if err := runSudo("ip", "netns", "exec", cfg.NSName, "ip", "link", "set", "dev", cfg.VethNS, "address", cfg.MACAddr); err != nil {
		return err
	}

	if err := runSudo("ip", "addr", "add", cfg.ProxyIP+"/24", "dev", cfg.VethHost); err != nil {
		return err
	}
	if err := runSudo("ip", "link", "set", cfg.VethHost, "up"); err != nil {
		return err
	}
	if err := runSudo("iptables", "-I", "INPUT", "-i", cfg.VethHost, "-j", "ACCEPT"); err != nil {
		return err
	}

	if err := runSudo("ip", "netns", "exec", cfg.NSName, "ip", "addr", "add", cfg.NSIP+"/24", "dev", cfg.VethNS); err != nil {
		return err
	}
	if err := runSudo("ip", "netns", "exec", cfg.NSName, "ip", "link", "set", cfg.VethNS, "up"); err != nil {
		return err
	}
	if err := runSudo("ip", "netns", "exec", cfg.NSName, "ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	if err := runSudo("ip", "netns", "exec", cfg.NSName, "sysctl", "-w", "net.ipv4.ping_group_range=0 2147483647"); err != nil {
		return err
	}

	if err := runSudo("ip", "netns", "exec", cfg.NSName, "ip", "tuntap", "add", "dev", "tun0", "mode", "tun"); err != nil {
		return err
	}
	// tun2socks relays raw IP packets read from the tun0 fd to the upstream
	// SOCKS5 proxy. Without a routable IPv4 address on tun0, the kernel
	// can't pick a source address for outbound IPv4 packets (default route
	// points at tun0) and tools that print the interface list — e.g. Node's
	// os.networkInterfaces() inside Trae — see tun0 with only an IPv6
	// link-local, which Trae interprets as "no network" and bails out
	// before completing OAuth. A /32 keeps the address off any subnet
	// route and avoids collision with the 10.250.x.0/24 used by the veth.
	if err := runSudo("ip", "netns", "exec", cfg.NSName, "ip", "addr", "add", "10.255.255.1/32", "dev", "tun0"); err != nil {
		return err
	}
	if err := runSudo("ip", "netns", "exec", cfg.NSName, "ip", "link", "set", "tun0", "up"); err != nil {
		return err
	}
	if err := runSudo("ip", "netns", "exec", cfg.NSName, "ip", "route", "add", "default", "dev", "tun0"); err != nil {
		return err
	}

	return nil
}

func TeardownNetwork(cfg HardwareConfig) {
	// Kill processes running inside the namespace first
	cmd := exec.Command("sudo", "ip", "netns", "pids", cfg.NSName)
	if out, err := cmd.Output(); err == nil {
		pidsStr := strings.TrimSpace(string(out))
		if pidsStr != "" {
			pids := strings.Fields(pidsStr)
			// Send SIGTERM
			killArgs := append([]string{"kill", "-TERM"}, pids...)
			exec.Command("sudo", killArgs...).Run()
			time.Sleep(500 * time.Millisecond)
			// Send SIGKILL
			killArgs = append([]string{"kill", "-KILL"}, pids...)
			exec.Command("sudo", killArgs...).Run()
		}
	}
	runSudo("iptables", "-D", "INPUT", "-i", cfg.VethHost, "-j", "ACCEPT")
	runSudo("ip", "netns", "delete", cfg.NSName)
	runSudo("ip", "link", "delete", cfg.VethHost)
}

func ListNamespaces() ([]string, error) {
	cmd := exec.Command("ip", "netns", "list")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var nsList []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) > 0 {
			nsList = append(nsList, parts[0])
		}
	}
	return nsList, nil
}
