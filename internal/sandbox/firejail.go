package sandbox

import (
	"fmt"
	"os"
)

func BuildProfileContent(identity, nativeProfile string) string {
	includeLine := ""
	etcList := "resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies"

	if nativeProfile != "" {
		etcList += ",fonts,ld.so.cache,ld.so.conf,ld.so.conf.d,localtime,nsswitch.conf,passwd,group,asound.conf,pulse"
		includeLine = fmt.Sprintf("include %s", nativeProfile)
	}

	content := fmt.Sprintf(`# Dynamic Security Profile for Identity: %s
%s

# Identity Spoofing
hostname %s
machine-id

# Block Hardware Telemetry
blacklist /sys/class/dmi
blacklist /sys/devices/virtual/dmi
blacklist /sys/class/firmware

nogroups
caps.drop all
seccomp
nonewprivs
noroot

# Route DNS
dns 127.0.0.1

private-dev
private-tmp
private-etc %s

read-only /sbin
read-only /usr/sbin
read-only /bin
read-only /usr/bin
whitelist /tmp/.X11-unix
`, identity, includeLine, identity, etcList)

	return content
}

func WriteProfile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}
