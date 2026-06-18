package proxy

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func StartTun2Socks(ctx context.Context, nsName string, proxyIP string, socksPort int) (*exec.Cmd, error) {
	socksProxy := fmt.Sprintf("socks5://%s:%d", proxyIP, socksPort)
	cmd := exec.CommandContext(ctx, "sudo", "ip", "netns", "exec", nsName, "tun2socks", "-device", "tun0", "-proxy", socksProxy)
	err := cmd.Start()
	if err != nil {
		return nil, err
	}

	// Brief sleep to catch immediate startup failures
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return nil, fmt.Errorf("tun2socks exited prematurely: %w", err)
	}
	return cmd, nil
}
