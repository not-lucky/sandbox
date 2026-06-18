package sandbox

import (
	"strings"
	"testing"
)

func TestBuildProfileContent(t *testing.T) {
	content := BuildProfileContent("my-id", "test.profile")

	if !strings.Contains(content, "hostname my-id") {
		t.Errorf("missing hostname directive")
	}
	if !strings.Contains(content, "include test.profile") {
		t.Errorf("missing include directive")
	}
	if !strings.Contains(content, "private-etc resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies,fonts,ld.so.cache,ld.so.conf,ld.so.conf.d,localtime,nsswitch.conf,passwd,group,asound.conf,pulse") {
		t.Errorf("missing extended private-etc")
	}

	contentNoNative := BuildProfileContent("my-id", "")
	if strings.Contains(contentNoNative, "include ") {
		t.Errorf("should not contain include")
	}
	if !strings.Contains(contentNoNative, "private-etc resolv.conf,hosts,ssl,ca-certificates,pki,crypto-policies\n") {
		t.Errorf("missing minimal private-etc")
	}
}
