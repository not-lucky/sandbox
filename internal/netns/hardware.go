package netns

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
)

type HardwareConfig struct {
	MACAddr   string
	NSName    string
	VethHost  string
	VethNS    string
	ProxyIP   string
	NSIP      string
	SocksPort int
}

const defaultSubnetPrefix = "10.250"

func GenerateHardwareConfig(identity string, socksPort int) HardwareConfig {
	hashBytes := md5.Sum([]byte(identity))
	hashHex := hex.EncodeToString(hashBytes[:])

	shortHash := hashHex[:6]
	macAddr := fmt.Sprintf("02:%s:%s:%s:%s:%s", hashHex[2:4], hashHex[4:6], hashHex[6:8], hashHex[8:10], hashHex[10:12])

	firstByteStr := hashHex[0:2]
	firstByteNum, _ := strconv.ParseInt(firstByteStr, 16, 64)
	octet := 1 + (firstByteNum % 254)

	return HardwareConfig{
		MACAddr:   macAddr,
		NSName:    "ns-" + shortHash,
		VethHost:  "vh-" + shortHash,
		VethNS:    "vn-" + shortHash,
		ProxyIP:   fmt.Sprintf("%s.%d.1", defaultSubnetPrefix, octet),
		NSIP:      fmt.Sprintf("%s.%d.2", defaultSubnetPrefix, octet),
		SocksPort: socksPort,
	}
}
