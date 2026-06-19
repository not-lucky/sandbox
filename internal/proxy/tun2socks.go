package proxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func StartTun2Socks(ctx context.Context, nsName string, proxyIP string, socksPort int) (*exec.Cmd, error) {
	socksProxy := fmt.Sprintf("socks5://%s:%d", proxyIP, socksPort)
	cmd := exec.CommandContext(ctx, "sudo", "ip", "netns", "exec", nsName, "tun2socks", "-device", "tun0", "-proxy", socksProxy)
	if logFile, err := os.OpenFile("/tmp/cloakid-tun2socks.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666); err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		defer logFile.Close()
	}
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
