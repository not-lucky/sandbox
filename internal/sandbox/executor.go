package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"cloakid/internal/logging"
)

type ExecuteOptions struct {
	NSName       string
	Identity     string
	HomeDir      string
	NoSandbox    bool
	Timeout      int
	CommandArgs  []string
	ProfilePath  string
	Whitelist    []string
	IdentityRoot string
	Cwd          string
}

var electronApps = map[string]bool{
	"trae": true, "code": true, "vscodium": true,
	"codium": true, "cursor": true, "obsidian": true,
}

func applyElectronWorkarounds(args []string, cmdBase string) []string {
	if !electronApps[cmdBase] {
		return args
	}
	for _, arg := range args {
		if arg == "--no-sandbox" {
			return args
		}
	}
	logging.Info("Detecting Electron-based application [%s]. Auto-appending --no-sandbox.", cmdBase)
	return append(args, "--no-sandbox")
}

func Execute(opts ExecuteOptions) error {
	cmdName := opts.CommandArgs[0]
	cmdBase := filepath.Base(cmdName)

	if !opts.NoSandbox {
		opts.CommandArgs = applyElectronWorkarounds(opts.CommandArgs, cmdBase)
	}

	pidFile := filepath.Join(opts.IdentityRoot, ".cloakid.pid")
	realHome, _ := os.UserHomeDir()
	realUser := os.Getenv("USER")

	var envArgs []string
	if opts.NoSandbox {
		envArgs = []string{
			"HOME=" + realHome,
			"USER=" + realUser,
			"LOGNAME=" + realUser,
			"PATH=" + os.Getenv("PATH"),
			"TERM=" + os.Getenv("TERM"),
			"COLORTERM=" + os.Getenv("COLORTERM"),
			"LANG=" + os.Getenv("LANG"),
			"SHELL=/bin/bash",
		}
		if d := os.Getenv("DISPLAY"); d != "" {
			envArgs = append(envArgs, "DISPLAY="+d)
		}
		if d := os.Getenv("WAYLAND_DISPLAY"); d != "" {
			envArgs = append(envArgs, "WAYLAND_DISPLAY="+d)
		}
		if d := os.Getenv("XAUTHORITY"); d != "" {
			envArgs = append(envArgs, "XAUTHORITY="+d)
		}
	} else {
		envArgs = []string{
			"HOME=" + opts.HomeDir,
			"XDG_CONFIG_HOME=" + filepath.Join(opts.HomeDir, ".config"),
			"XDG_DATA_HOME=" + filepath.Join(opts.HomeDir, ".local", "share"),
			"XDG_STATE_HOME=" + filepath.Join(opts.HomeDir, ".local", "state"),
			"XDG_CACHE_HOME=" + filepath.Join(opts.HomeDir, ".cache"),
			"TERM=" + os.Getenv("TERM"),
			"COLORTERM=" + os.Getenv("COLORTERM"),
			"LANG=" + os.Getenv("LANG"),
			"USER=user",
			"LOGNAME=user",
			"SHELL=/bin/bash",
			"PATH=" + realHome + "/.local/bin:/usr/local/bin:/usr/bin:/bin",
		}
		if d := os.Getenv("DISPLAY"); d != "" {
			envArgs = append(envArgs, "DISPLAY="+d)
		}
		if d := os.Getenv("WAYLAND_DISPLAY"); d != "" {
			envArgs = append(envArgs, "WAYLAND_DISPLAY="+d)
		}
		if d := os.Getenv("XAUTHORITY"); d != "" {
			envArgs = append(envArgs, "XAUTHORITY="+d)
			opts.Whitelist = append(opts.Whitelist, "--whitelist="+d)
		}
		if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
			envArgs = append(envArgs, "XDG_RUNTIME_DIR="+d)
		}
	}

	var timeoutArgs []string
	if opts.Timeout > 0 {
		timeoutArgs = []string{"timeout", "--signal=TERM", "--kill-after=5", strconv.Itoa(opts.Timeout)}
	}

	baseArgs := []string{"ip", "netns", "exec", opts.NSName, "sudo", "-u", realUser, "env", "-i"}
	baseArgs = append(baseArgs, envArgs...)
	baseArgs = append(baseArgs, timeoutArgs...)

	var finalArgs []string
	if opts.NoSandbox {
		finalArgs = opts.CommandArgs
	} else {
		firejailArgs := []string{
			"firejail",
			"--deterministic-shutdown",
			"--deterministic-exit-code",
			"--profile=" + opts.ProfilePath,
		}
		firejailArgs = append(firejailArgs, opts.Whitelist...)
		if opts.Cwd != "" {
			firejailArgs = append(firejailArgs, "--private-cwd="+opts.Cwd)
		}
		firejailArgs = append(firejailArgs, "--")
		firejailArgs = append(firejailArgs, opts.CommandArgs...)
		finalArgs = firejailArgs
	}

	cmdArgs := append(baseArgs, finalArgs...)
	cmd := exec.Command("sudo", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sandbox: %w", err)
	}

	// Write PID file
	os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	defer os.Remove(pidFile)

	return cmd.Wait()
}
