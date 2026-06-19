package sandbox

import (
	"fmt"
	"os"
)

func BuildProfileContent(identity, nativeProfile, cmdName string) string {
	includeLine := ""
	etcList := "resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies"

	if nativeProfile != "" {
		etcList += ",fonts,ld.so.cache,ld.so.conf,ld.so.conf.d,localtime,nsswitch.conf,passwd,group,asound.conf,pulse"
		includeLine = fmt.Sprintf("include %s", nativeProfile)
	}

	// Electron apps use bwrap internally, which requires clone/unshare
	// syscalls and new-privilege capabilities. Firefox uses namespaces for
	// its sandbox. Use a targeted seccomp.drop blocklist instead of blanket
	// seccomp, and omit nonewprivs/noroot.
	var seccompBlock string
	if electronApps[cmdName] || firefoxApps[cmdName] {
		secCompType := "Electron/bwrap"
		if firefoxApps[cmdName] {
			secCompType = "Firefox namespaces"
		}
		seccompBlock = fmt.Sprintf(`# Relaxed seccomp for %s compatibility
seccomp.drop @clock,@debug,@module,@raw-io,@reboot,@swap,acct,add_key,bpf,fanotify_init,io_cancel,io_destroy,io_getevents,io_setup,io_submit,ioperm,iopl,kcmp,kexec_file_load,kexec_load,keyctl,lookup_dcookie,mbind,migrate_pages,move_pages,nfsservctl,open_by_handle_at,perf_event_open,personality,process_vm_readv,process_vm_writev,ptrace,remap_file_pages,request_key,set_mempolicy,syslog,userfaultfd,vhangup,vmsplice`, secCompType)
	} else {
		seccompBlock = `seccomp
nonewprivs
noroot`
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
%s

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
`, identity, includeLine, identity, seccompBlock, etcList)

	return content
}

func WriteProfile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}
