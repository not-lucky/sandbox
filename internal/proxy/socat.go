package proxy

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func StartSocat(ctx context.Context, proxyIP string, socksPort int) (*exec.Cmd, error) {
	bindStr := fmt.Sprintf("TCP-LISTEN:%d,bind=%s,fork,reuseaddr", socksPort, proxyIP)
	destStr := fmt.Sprintf("TCP:127.0.0.1:%d", socksPort)
	cmd := exec.CommandContext(ctx, "socat", bindStr, destStr)
	err := cmd.Start()
	if err != nil {
		return nil, err
	}

	// Brief sleep to catch immediate startup failures
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return nil, fmt.Errorf("socat exited prematurely: %w", err)
	}
	return cmd, nil
}
