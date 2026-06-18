package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Unsetenv("XDG_CONFIG_HOME")

	cloakDir := filepath.Join(tmpDir, "cloakid")
	if err := os.MkdirAll(cloakDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	yamlData := `
default_identity: "test-id"
default_dns: "8.8.8.8"
default_socks_port: 9000
default_timeout: 60
verbose: true
no_sandbox: true
`
	err := os.WriteFile(filepath.Join(cloakDir, "config.yaml"), []byte(yamlData), 0644)
	if err != nil {
		t.Fatalf("failed to write config yaml: %v", err)
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.DefaultIdentity != "test-id" {
		t.Errorf("DefaultIdentity got %q, want 'test-id'", cfg.DefaultIdentity)
	}
	if cfg.DefaultDNS != "8.8.8.8" {
		t.Errorf("DefaultDNS got %q, want '8.8.8.8'", cfg.DefaultDNS)
	}
	if cfg.DefaultSOCKSPort != 9000 {
		t.Errorf("DefaultSOCKSPort got %d, want 9000", cfg.DefaultSOCKSPort)
	}
	if cfg.DefaultTimeout != 60 {
		t.Errorf("DefaultTimeout got %d, want 60", cfg.DefaultTimeout)
	}
	if !cfg.Verbose {
		t.Errorf("Verbose got %v, want true", cfg.Verbose)
	}
	if !cfg.NoSandbox {
		t.Errorf("NoSandbox got %v, want true", cfg.NoSandbox)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	os.Setenv("XDG_CONFIG_HOME", t.TempDir()) // empty dir
	defer os.Unsetenv("XDG_CONFIG_HOME")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed on missing file: %v", err)
	}

	if cfg.DefaultDNS != "1.1.1.1" {
		t.Errorf("DefaultDNS got %q, want '1.1.1.1'", cfg.DefaultDNS)
	}
	if cfg.DefaultSOCKSPort != 10808 {
		t.Errorf("DefaultSOCKSPort got %d, want 10808", cfg.DefaultSOCKSPort)
	}
}
