package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"cloakid/internal/logging"
)

type ExecuteOptions struct {
	NSName       string
	Identity     string
	HomeDir      string
	NoSandbox    bool
	NoProxy      bool
	Timeout      int
	CommandArgs  []string
	ProfilePath  string
	Whitelist    []string
	IdentityRoot string
	Cwd          string

	// Quiet routes the inner command's stdout/stderr into a timestamped
	// file under /tmp instead of the terminal. Stdin is preserved.
	Quiet bool
}

var electronApps = map[string]bool{
	"trae": true, "code": true, "vscodium": true,
	"codium": true, "cursor": true, "obsidian": true,
}

var firefoxApps = map[string]bool{
	"firefox": true, "firefox-esr": true, "mullvadbrowser": true,
	"librewolf": true, "waterfox": true,
}

// traeApps lists commands that ship a bundled libstdc++ too old for the
// system libicuuc (GLIBCXX_3.4.30 not found). For these we prepend the
// system libstdc++ via LD_LIBRARY_PATH.
var traeApps = map[string]bool{
	"trae": true,
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

func applyFirefoxWorkarounds(cmdBase string) []string {
	if !firefoxApps[cmdBase] {
		return nil
	}
	logging.Info("Detecting Firefox-based application [%s]. Setting MOZ_DISABLE_*_SANDBOX environment variables.", cmdBase)
	return []string{
		"MOZ_DISABLE_CONTENT_SANDBOX=1",
		"MOZ_DISABLE_GMP_SANDBOX=1",
		"MOZ_DISABLE_RDD_SANDBOX=1",
		"MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1",
	}
}

func applyTraeWorkarounds(cmdBase string) []string {
	if !traeApps[cmdBase] {
		return nil
	}
	logging.Info("Detecting trae [libstdc++ mismatch]. Prepending /usr/lib to LD_LIBRARY_PATH.")
	return []string{"LD_LIBRARY_PATH=/usr/lib"}
}

func buildEnvArgs(opts ExecuteOptions, realHome, realUser string) ([]string, []string) {
	var envArgs []string
	var extraWhitelist []string

	cmdBase := ""
	if len(opts.CommandArgs) > 0 {
		cmdBase = filepath.Base(opts.CommandArgs[0])
	}

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
		firefoxEnv := applyFirefoxWorkarounds(cmdBase)
		envArgs = append(envArgs, firefoxEnv...)
		traeEnv := applyTraeWorkarounds(cmdBase)
		envArgs = append(envArgs, traeEnv...)
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
		if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
			envArgs = append(envArgs, "XDG_RUNTIME_DIR="+d)
		}
		firefoxEnv := applyFirefoxWorkarounds(cmdBase)
		envArgs = append(envArgs, firefoxEnv...)
		traeEnv := applyTraeWorkarounds(cmdBase)
		envArgs = append(envArgs, traeEnv...)
	}

	// Common display envs
	if d := os.Getenv("DISPLAY"); d != "" {
		envArgs = append(envArgs, "DISPLAY="+d)
	}
	if d := os.Getenv("WAYLAND_DISPLAY"); d != "" {
		envArgs = append(envArgs, "WAYLAND_DISPLAY="+d)
	}
	if d := os.Getenv("XAUTHORITY"); d != "" {
		envArgs = append(envArgs, "XAUTHORITY="+d)
		if !opts.NoSandbox {
			extraWhitelist = append(extraWhitelist, "--whitelist="+d)
		}
	}

	return envArgs, extraWhitelist
}

func buildCommandArgs(opts *ExecuteOptions, realHome, realUser string) []string {
	cmdBase := filepath.Base(opts.CommandArgs[0])

	if !opts.NoSandbox {
		opts.CommandArgs = applyElectronWorkarounds(opts.CommandArgs, cmdBase)
	}

	envArgs, extraWhitelist := buildEnvArgs(*opts, realHome, realUser)
	opts.Whitelist = append(opts.Whitelist, extraWhitelist...)

	var timeoutArgs []string
	if opts.Timeout > 0 {
		timeoutArgs = []string{"timeout", "--signal=TERM", "--kill-after=5", strconv.Itoa(opts.Timeout)}
	}

	var baseArgs []string
	if opts.NoProxy {
		baseArgs = []string{"-u", realUser, "env", "-i"}
	} else {
		baseArgs = []string{"ip", "netns", "exec", opts.NSName, "sudo", "-u", realUser, "env", "-i"}
	}
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

	return append(baseArgs, finalArgs...)
}

func Execute(opts ExecuteOptions) error {
	realHome, _ := os.UserHomeDir()
	realUser := os.Getenv("USER")

	cmdArgs := buildCommandArgs(&opts, realHome, realUser)

	cmd := exec.Command("sudo", cmdArgs...)

	if err := configureStreams(cmd, opts.Identity, opts.Quiet); err != nil {
		return err
	}

	// Close the quiet log file on every return path; cmd.Start() may fail.
	if opts.Quiet {
		defer func() {
			if f, ok := cmd.Stdout.(*os.File); ok {
				_ = f.Close()
			}
		}()
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sandbox: %w", err)
	}

	pidFile := filepath.Join(opts.IdentityRoot, ".cloakid.pid")
	os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	defer os.Remove(pidFile)

	return cmd.Wait()
}

// configureStreams wires the child's stdio. When quiet is true, both
// stdout and stderr are routed to a fresh timestamped log file under /tmp
// (one file per run); stdin is always preserved so interactive prompts
// still work. When quiet is false, all three streams pass through to the
// terminal unchanged.
func configureStreams(cmd *exec.Cmd, identity string, quiet bool) error {
	cmd.Stdin = os.Stdin
	if !quiet {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return nil
	}
	path := quietLogPath(identity, time.Now())
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("quiet mode: open log file: %w", err)
	}
	cmd.Stdout = f
	cmd.Stderr = f
	logging.Info("Quiet mode: child output -> %s", path)
	return nil
}

// quietLogPath builds the per-run timestamped log file path used by --quiet.
func quietLogPath(identity string, now time.Time) string {
	return fmt.Sprintf("/tmp/cloakid-quiet-%s-%s.log", identity, now.Format("20060102-150405"))
}
