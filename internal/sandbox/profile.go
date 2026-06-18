package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ResolveProfile(cmdName string, userProfile string) string {
	if userProfile != "" {
		if strings.HasPrefix(userProfile, "~/") {
			home, err := os.UserHomeDir()
			if err == nil {
				userProfile = filepath.Join(home, userProfile[2:])
			}
		}
		if filepath.IsAbs(userProfile) {
			return userProfile
		}
		if filepath.Ext(userProfile) == "" {
			return userProfile + ".profile"
		}
		return userProfile
	}

	cmdPath, err := exec.LookPath(cmdName)
	if err == nil {
		cmdName = filepath.Base(cmdPath)
	} else {
		cmdName = filepath.Base(cmdName)
	}

	home, _ := os.UserHomeDir()
	localProfile := filepath.Join(home, ".config", "firejail", cmdName+".profile")
	if _, err := os.Stat(localProfile); err == nil {
		return cmdName + ".profile"
	}

	sysProfile := filepath.Join("/etc", "firejail", cmdName+".profile")
	if _, err := os.Stat(sysProfile); err == nil {
		return cmdName + ".profile"
	}

	if cmdName == "vscodium" || cmdName == "trae" || cmdName == "cursor" || cmdName == "code" {
		codiumProfile := filepath.Join("/etc", "firejail", "codium.profile")
		if _, err := os.Stat(codiumProfile); err == nil {
			return "codium.profile"
		}
	}
	return ""
}
