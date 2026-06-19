package sandbox

import (
	"reflect"
	"strings"
	"testing"
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
