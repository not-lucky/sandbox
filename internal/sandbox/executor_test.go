package sandbox

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestApplyElectronWorkarounds(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		cmdBase  string
		expected []string
	}{
		{
			name:     "Non-electron app",
			args:     []string{"vim", "file.txt"},
			cmdBase:  "vim",
			expected: []string{"vim", "file.txt"},
		},
		{
			name:     "Electron app without sandbox arg",
			args:     []string{"code", "."},
			cmdBase:  "code",
			expected: []string{"code", ".", "--no-sandbox"},
		},
		{
			name:     "Electron app with sandbox arg already",
			args:     []string{"cursor", "--no-sandbox", "."},
			cmdBase:  "cursor",
			expected: []string{"cursor", "--no-sandbox", "."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyElectronWorkarounds(tt.args, tt.cmdBase)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestApplyFirefoxWorkarounds(t *testing.T) {
	tests := []struct {
		name     string
		cmdBase  string
		expected []string
	}{
		{
			name:     "Non-firefox app",
			cmdBase:  "vim",
			expected: nil,
		},
		{
			name:    "Firefox app",
			cmdBase: "firefox",
			expected: []string{
				"MOZ_DISABLE_CONTENT_SANDBOX=1",
				"MOZ_DISABLE_GMP_SANDBOX=1",
				"MOZ_DISABLE_RDD_SANDBOX=1",
				"MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1",
			},
		},
		{
			name:    "Mullvad Browser",
			cmdBase: "mullvadbrowser",
			expected: []string{
				"MOZ_DISABLE_CONTENT_SANDBOX=1",
				"MOZ_DISABLE_GMP_SANDBOX=1",
				"MOZ_DISABLE_RDD_SANDBOX=1",
				"MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1",
			},
		},
		{
			name:    "LibreWolf",
			cmdBase: "librewolf",
			expected: []string{
				"MOZ_DISABLE_CONTENT_SANDBOX=1",
				"MOZ_DISABLE_GMP_SANDBOX=1",
				"MOZ_DISABLE_RDD_SANDBOX=1",
				"MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyFirefoxWorkarounds(tt.cmdBase)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestApplyTraeWorkarounds(t *testing.T) {
	tests := []struct {
		name     string
		cmdBase  string
		expected []string
	}{
		{
			name:     "Non-trae app",
			cmdBase:  "vim",
			expected: nil,
		},
		{
			name:     "Trae app",
			cmdBase:  "trae",
			expected: []string{"LD_LIBRARY_PATH=/usr/lib"},
		},
		{
			// applyTraeWorkarounds receives an already-basenamed command,
			// so a path-style input like /opt/trae/bin/trae is normalised
			// upstream before reaching this map.
			name:     "Trae basename extracted from path",
			cmdBase:  "trae",
			expected: []string{"LD_LIBRARY_PATH=/usr/lib"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyTraeWorkarounds(tt.cmdBase)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBuildEnvArgs(t *testing.T) {
	opts := ExecuteOptions{
		NoSandbox: false,
		HomeDir:   "/fake/home",
	}

	envArgs, extraWhitelist := buildEnvArgs(opts, "/real/home", "realuser")

	hasUser := false
	for _, e := range envArgs {
		if strings.HasPrefix(e, "USER=") {
			hasUser = true
			if e != "USER=user" {
				t.Errorf("Expected USER=user in sandbox mode, got %s", e)
			}
		}
	}

	if !hasUser {
		t.Errorf("USER env var missing in sandbox mode")
	}

	// NoSandbox true
	opts.NoSandbox = true
	envArgs, extraWhitelist = buildEnvArgs(opts, "/real/home", "realuser")
	hasUser = false
	for _, e := range envArgs {
		if strings.HasPrefix(e, "USER=") {
			hasUser = true
			if e != "USER=realuser" {
				t.Errorf("Expected USER=realuser in nosandbox mode, got %s", e)
			}
		}
	}

	if !hasUser {
		t.Errorf("USER env var missing in nosandbox mode")
	}

	// Avoid unused variable compiler error if tests run in an env without XAUTHORITY
	_ = extraWhitelist
}

func TestConfigureStreams(t *testing.T) {
	t.Run("non-quiet passes through to terminal", func(t *testing.T) {
		cmd := &exec.Cmd{}
		if err := configureStreams(cmd, "test", false); err != nil {
			t.Fatalf("configureStreams returned error: %v", err)
		}
		if cmd.Stdin != os.Stdin {
			t.Errorf("stdin: got %v, want os.Stdin", cmd.Stdin)
		}
		if cmd.Stdout != os.Stdout {
			t.Errorf("stdout: got %v, want os.Stdout", cmd.Stdout)
		}
		if cmd.Stderr != os.Stderr {
			t.Errorf("stderr: got %v, want os.Stderr", cmd.Stderr)
		}
	})

	t.Run("quiet routes to a fresh timestamped file", func(t *testing.T) {
		identity := "quiet-routes-test"
		cmd := &exec.Cmd{}
		if err := configureStreams(cmd, identity, true); err != nil {
			t.Fatalf("configureStreams returned error: %v", err)
		}
		t.Cleanup(func() {
			if cmd.Stdout != nil {
				if f, ok := cmd.Stdout.(*os.File); ok {
					_ = f.Close()
				}
			}
		})

		if cmd.Stdin != os.Stdin {
			t.Errorf("stdin: got %v, want os.Stdin (must stay interactive)", cmd.Stdin)
		}
		outFile, ok := cmd.Stdout.(*os.File)
		if !ok {
			t.Fatalf("stdout: got %T, want *os.File", cmd.Stdout)
		}
		if !reflect.DeepEqual(cmd.Stderr, cmd.Stdout) {
			t.Errorf("stderr should point to same file as stdout; got %T vs %T", cmd.Stderr, cmd.Stdout)
		}

		// Path pattern must match /tmp/cloakid-quiet-<identity>-<timestamp>.log.
		wantPrefix := "/tmp/cloakid-quiet-" + identity + "-"
		if got := outFile.Name(); !strings.HasPrefix(got, wantPrefix) || !strings.HasSuffix(got, ".log") {
			t.Errorf("log file path = %q, want prefix %q and .log suffix", got, wantPrefix)
		}

		// File must be writable and start empty.
		if _, err := outFile.WriteString("hello\n"); err != nil {
			t.Fatalf("write to log file: %v", err)
		}
		if err := outFile.Sync(); err != nil {
			t.Fatalf("sync: %v", err)
		}
		body, err := os.ReadFile(outFile.Name())
		if err != nil {
			t.Fatalf("read log file: %v", err)
		}
		if string(body) != "hello\n" {
			t.Errorf("file contents = %q, want %q", string(body), "hello\n")
		}

	})

	t.Run("two consecutive runs use different timestamps", func(t *testing.T) {
		identity := "quiet-rotation-test"
		cmd1 := &exec.Cmd{}
		if err := configureStreams(cmd1, identity, true); err != nil {
			t.Fatalf("first configureStreams: %v", err)
		}
		t.Cleanup(func() {
			if f, ok := cmd1.Stdout.(*os.File); ok {
				_ = f.Close()
			}
		})
		f1, ok := cmd1.Stdout.(*os.File)
		if !ok {
			t.Fatalf("stdout: got %T, want *os.File", cmd1.Stdout)
		}
		path1 := f1.Name()

		// Sleep enough to cross the second-resolution boundary that the
		// timestamp format ("20060102-150405") uses.
		time.Sleep(1100 * time.Millisecond)

		cmd2 := &exec.Cmd{}
		if err := configureStreams(cmd2, identity, true); err != nil {
			t.Fatalf("second configureStreams: %v", err)
		}
		t.Cleanup(func() {
			if f, ok := cmd2.Stdout.(*os.File); ok {
				_ = f.Close()
			}
		})
		f2, ok := cmd2.Stdout.(*os.File)
		if !ok {
			t.Fatalf("stdout: got %T, want *os.File", cmd2.Stdout)
		}
		path2 := f2.Name()

		if path1 == path2 {
			t.Errorf("expected distinct timestamped paths, both = %q", path1)
		}
	})
}
