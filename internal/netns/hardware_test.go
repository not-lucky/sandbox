package netns

import (
	"testing"
)

func TestGenerateHardwareConfig(t *testing.T) {
	// md5("test") = 098f6bcd4621d373cade4e832627b4f6
	// shortHash = 098f6b
	// mac = 02:8f:6b:cd:46:21
	// octet = 1 + (9 % 254) = 10 (since 0x09 is 9, 9%254 = 9, 1+9 = 10)
	cfg := GenerateHardwareConfig("test", 10808)

	if cfg.MACAddr != "02:8f:6b:cd:46:21" {
		t.Errorf("got mac %q, want 02:8f:6b:cd:46:21", cfg.MACAddr)
	}
	if cfg.NSName != "ns-098f6b" {
		t.Errorf("got nsname %q, want ns-098f6b", cfg.NSName)
	}
	if cfg.VethHost != "vh-098f6b" {
		t.Errorf("got vethhost %q, want vh-098f6b", cfg.VethHost)
	}
	if cfg.VethNS != "vn-098f6b" {
		t.Errorf("got vethns %q, want vn-098f6b", cfg.VethNS)
	}
	if cfg.ProxyIP != "10.250.10.1" {
		t.Errorf("got proxyip %q, want 10.250.10.1", cfg.ProxyIP)
	}
	if cfg.NSIP != "10.250.10.2" {
		t.Errorf("got nsip %q, want 10.250.10.2", cfg.NSIP)
	}
	if cfg.SocksPort != 10808 {
		t.Errorf("got port %d, want 10808", cfg.SocksPort)
	}
}
