// Package proxy provides network proxying functionality for CloakID.
// It handles DNS over TCP conversion, SOCKS5 bridging via socat,
// tun2socks routing, and port forwarding for network namespace isolation.
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"cloakid/internal/logging"
)

// PortMapping represents a mapping between a host port and a namespace port.
type PortMapping struct {
	// HostPort is the port number on the host system.
	HostPort int
	// NSPort is the port number inside the network namespace.
	NSPort int
}

// ParsePortMappings parses a comma-separated list of port mappings (e.g. "38085" or "8080:80,38085")
func ParsePortMappings(s string) ([]PortMapping, error) {
	var mappings []PortMapping
	if s == "" {
		return mappings, nil
	}
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var hostPort, nsPort int
		var err error
		if strings.Contains(part, ":") {
			subParts := strings.Split(part, ":")
			if len(subParts) != 2 {
				return nil, fmt.Errorf("invalid port mapping format: %s", part)
			}
			hostPort, err = strconv.Atoi(strings.TrimSpace(subParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid host port %s: %w", subParts[0], err)
			}
			nsPort, err = strconv.Atoi(strings.TrimSpace(subParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid namespace port %s: %w", subParts[1], err)
			}
		} else {
			hostPort, err = strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %w", part, err)
			}
			nsPort = hostPort
		}
		mappings = append(mappings, PortMapping{HostPort: hostPort, NSPort: nsPort})
	}
	return mappings, nil
}

// CheckPortConflict checks if the given port is already in use on local IP addresses
func CheckPortConflict(ip string, port int) error {
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
			if host == "0.0.0.0" || host == "::" || host == "*" || host == "" || host == ip {
				return fmt.Errorf("port %d is already in use on address %s", port, localAddr)
			}
		}
	}
	return nil
}

// StartPortForwarding starts a host-side socat process that forwards local connections to the netns
func StartPortForwarding(ctx context.Context, nsName string, hostPort int, nsPort int) (*exec.Cmd, error) {
	bindStr := fmt.Sprintf("TCP-LISTEN:%d,bind=127.0.0.1,fork,reuseaddr", hostPort)
	execStr := fmt.Sprintf("ip netns exec %s socat - 'TCP:127.0.0.1:%d'", nsName, nsPort)
	cmd := exec.CommandContext(ctx, "sudo", "socat", "-d", "-d", bindStr, fmt.Sprintf("EXEC:%s", execStr))

	logging.Info("Forwarding host TCP port %d to namespace TCP port %d", hostPort, nsPort)
	logging.Debug("Starting port forwarding command: sudo socat %s EXEC:%q", bindStr, execStr)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	logFile, err := os.OpenFile(fmt.Sprintf("/tmp/cloakid-forward-%d.log", hostPort), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		defer logFile.Close()
	}

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- cmd.Wait()
	}()

	select {
	case err := <-errChan:
		return nil, fmt.Errorf("port forwarding exited prematurely: %v (stderr: %s)", err, stderr.String())
	case <-time.After(150 * time.Millisecond):
		return cmd, nil
	}
}

// AutoForwarder automatically detects and forwards ports from the network namespace to the host.
// It monitors the namespace for new listening ports and creates forwarders for them,
// removing forwarders when ports stop listening.
type AutoForwarder struct {
	NSName    string
	socksPort int
	ctx       context.Context
	cancel    context.CancelFunc
	active    map[int]*exec.Cmd
}

// NewAutoForwarder creates a new AutoForwarder for the specified namespace and SOCKS port.
func NewAutoForwarder(ctx context.Context, nsName string, socksPort int) *AutoForwarder {
	subCtx, cancel := context.WithCancel(ctx)
	return &AutoForwarder{
		NSName:    nsName,
		socksPort: socksPort,
		ctx:       subCtx,
		cancel:    cancel,
		active:    make(map[int]*exec.Cmd),
	}
}

// Start begins monitoring the network namespace for listening ports and automatically
// creates forwarders for new ports. It runs in a background goroutine.
func (af *AutoForwarder) Start() {
	go func() {
		logging.Info("AutoForwarder started for namespace %s", af.NSName)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		defer af.StopAll()

		for {
			select {
			case <-af.ctx.Done():
				return
			case <-ticker.C:
				ports, err := af.getNSListeningPorts()
				if err != nil {
					logging.Debug("AutoForwarder: failed to get namespace listening ports: %v", err)
					continue
				}
				af.reconcile(ports)
			}
		}
	}()
}

// getNSListeningPorts queries the network namespace to find all currently listening TCP ports.
func (af *AutoForwarder) getNSListeningPorts() (map[int]bool, error) {
	cmd := exec.Command("sudo", "ip", "netns", "exec", af.NSName, "ss", "-tln")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	ports := make(map[int]bool)
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddr := fields[3]
		idx := strings.LastIndex(localAddr, ":")
		if idx == -1 {
			continue
		}
		portStr := localAddr[idx+1:]
		port, err := strconv.Atoi(portStr)
		if err == nil {
			if port != 53 && port != af.socksPort {
				ports[port] = true
			}
		}
	}
	return ports, nil
}

// reconcile compares the currently active forwarders with the actual listening ports
// in the namespace, starting forwarders for new ports and stopping forwarders for
// ports that are no longer listening.
func (af *AutoForwarder) reconcile(nsPorts map[int]bool) {
	// 1. Stop forwarding for ports that are no longer listening
	for port, cmd := range af.active {
		if !nsPorts[port] {
			logging.Info("AutoForwarder: Port %d stopped listening inside namespace. Stopping forwarder...", port)
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			delete(af.active, port)
		}
	}

	// 2. Start forwarding for new listening ports
	for port := range nsPorts {
		if _, exists := af.active[port]; !exists {
			if err := CheckPortConflict("127.0.0.1", port); err != nil {
				logging.Warn("AutoForwarder: Port %d started listening inside namespace, but host port is already in use: %v. Skipping...", port, err)
				continue
			}

			logging.Info("AutoForwarder: Detected new listening port %d inside namespace. Starting forwarder...", port)
			cmd, err := StartPortForwarding(af.ctx, af.NSName, port, port)
			if err != nil {
				logging.Error("AutoForwarder: Failed to start port forwarding for port %d: %v", port, err)
				continue
			}
			af.active[port] = cmd
		}
	}
}

// StopAll kills all active port forwarding processes.
func (af *AutoForwarder) StopAll() {
	for port, cmd := range af.active {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		delete(af.active, port)
	}
}

// Stop stops the AutoForwarder monitoring goroutine and cleans up all active forwarders.
func (af *AutoForwarder) Stop() {
	af.cancel()
}
