package sandbox

import (
	"strings"
	"testing"
)

func TestBuildProfileContent(t *testing.T) {
	content := BuildProfileContent("my-id", "test.profile", "bash", false)

	if !strings.Contains(content, "hostname my-id") {
		t.Errorf("missing hostname directive")
	}
	if !strings.Contains(content, "include test.profile") {
		t.Errorf("missing include directive")
	}
	if !strings.Contains(content, "private-etc resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies,fonts,ld.so.cache,ld.so.conf,ld.so.conf.d,localtime,nsswitch.conf,passwd,group,asound.conf,pulse") {
		t.Errorf("missing extended private-etc")
	}

	contentNoNative := BuildProfileContent("my-id", "", "bash", false)
	if strings.Contains(contentNoNative, "include ") {
		t.Errorf("should not contain include")
	}
	if !strings.Contains(contentNoNative, "private-etc resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies\n") {
		t.Errorf("missing minimal private-etc")
	}
}

func TestBuildProfileContentStrictSeccomp(t *testing.T) {
	// Non-Electron/non-Firefox apps should get blanket seccomp + nonewprivs + noroot
	for _, cmd := range []string{"bash", "vim", "npm"} {
		content := BuildProfileContent("test-id", "", cmd, false)
		if !strings.Contains(content, "\nseccomp\n") {
			t.Errorf("cmd=%s: expected blanket 'seccomp' directive", cmd)
		}
		if !strings.Contains(content, "\nnonewprivs\n") {
			t.Errorf("cmd=%s: expected 'nonewprivs' directive", cmd)
		}
		if !strings.Contains(content, "\nnoroot\n") {
			t.Errorf("cmd=%s: expected 'noroot' directive", cmd)
		}
		if strings.Contains(content, "seccomp.drop") {
			t.Errorf("cmd=%s: non-Electron/non-Firefox app should not have seccomp.drop", cmd)
		}
	}
}

func TestBuildProfileContentElectronRelaxed(t *testing.T) {
	// Every Electron app in the electronApps map should get the relaxed
	// seccomp.drop profile and must NOT have nonewprivs/noroot.
	for cmd := range electronApps {
		content := BuildProfileContent("test-id", "", cmd, false)
		if !strings.Contains(content, "seccomp.drop") {
			t.Errorf("cmd=%s: expected 'seccomp.drop' for Electron app", cmd)
		}
		if strings.Contains(content, "\nnonewprivs\n") {
			t.Errorf("cmd=%s: Electron app must not have 'nonewprivs'", cmd)
		}
		if strings.Contains(content, "\nnoroot\n") {
			t.Errorf("cmd=%s: Electron app must not have 'noroot'", cmd)
		}
		// Blanket seccomp must not appear (only seccomp.drop)
		if strings.Contains(content, "\nseccomp\n") {
			t.Errorf("cmd=%s: Electron app must not have blanket 'seccomp'", cmd)
		}
	}
}

func TestBuildProfileContentFirefoxRelaxed(t *testing.T) {
	// Every Firefox app in the firefoxApps map should get the relaxed
	// seccomp.drop profile and must NOT have nonewprivs/noroot.
	for cmd := range firefoxApps {
		content := BuildProfileContent("test-id", "", cmd, false)
		if !strings.Contains(content, "seccomp.drop") {
			t.Errorf("cmd=%s: expected 'seccomp.drop' for Firefox app", cmd)
		}
		if strings.Contains(content, "\nnonewprivs\n") {
			t.Errorf("cmd=%s: Firefox app must not have 'nonewprivs'", cmd)
		}
		if strings.Contains(content, "\nnoroot\n") {
			t.Errorf("cmd=%s: Firefox app must not have 'noroot'", cmd)
		}
		// Blanket seccomp must not appear (only seccomp.drop)
		if strings.Contains(content, "\nseccomp\n") {
			t.Errorf("cmd=%s: Firefox app must not have blanket 'seccomp'", cmd)
		}
	}
}

func TestBuildProfileContentNoProxy(t *testing.T) {
	contentProxy := BuildProfileContent("my-id", "", "bash", false)
	if !strings.Contains(contentProxy, "dns 127.0.0.1") {
		t.Errorf("expected dns directive when proxy is enabled")
	}

	contentNoProxy := BuildProfileContent("my-id", "", "bash", true)
	if strings.Contains(contentNoProxy, "dns 127.0.0.1") {
		t.Errorf("expected no dns directive when proxy is disabled")
	}
}
