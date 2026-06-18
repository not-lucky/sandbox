package identity

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

func IsSandboxPID(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return false
	}
	cmdline := string(data)
	return strings.Contains(cmdline, "firejail") || strings.Contains(cmdline, "cloakid") || strings.Contains(cmdline, "sandbox")
}

var nameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func Sanitize(name string) string {
	return nameSanitizer.ReplaceAllString(name, "")
}

func GetIdentitiesRoot() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cloakid_identities")
}

func GetIdentityPath(name string) string {
	return filepath.Join(GetIdentitiesRoot(), Sanitize(name))
}

func GetIdentityHome(name string) string {
	return filepath.Join(GetIdentityPath(name), "home")
}

func GetIdentityConfigs(name string) string {
	return filepath.Join(GetIdentityPath(name), ".cloakid_configs")
}

func GetPIDFile(name string) string {
	return filepath.Join(GetIdentityPath(name), ".cloakid.pid")
}

func Hash(name string) string {
	hashBytes := md5.Sum([]byte(name))
	return hex.EncodeToString(hashBytes[:])[:6]
}

func EnsureDirs(name string) error {
	dirs := []string{
		GetIdentityPath(name),
		GetIdentityHome(name),
		GetIdentityConfigs(name),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}
