package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"cloakid/internal/logging"
)

var defaultFallbackServers = []string{
	"156.154.70.1:53", "156.154.71.1:53", "199.85.126.10:53", "9.9.9.9:53",
	"1.0.0.1:53", "64.6.65.6:53", "199.85.127.10:53", "195.46.39.39:53",
	"8.8.8.8:53", "208.67.222.222:53", "8.8.4.4:53", "149.112.112.112:53",
	"208.67.220.220:53", "195.46.39.40:53", "209.244.0.3:53", "119.29.29.29:53",
	"223.5.5.5:53", "223.6.6.6:53", "209.244.0.4:53", "119.28.28.28:53",
	"64.6.64.6:53", "210.2.4.8:53", "74.82.42.42:53", "8.26.56.26:53",
	"80.80.81.81:53", "84.200.70.40:53", "8.20.247.20:53", "1.2.4.8:53",
	"84.200.69.80:53", "77.88.8.8:53", "216.146.35.35:53", "77.88.8.1:53",
	"216.146.36.36:53", "80.80.80.80:53", "117.50.22.22:53", "218.30.118.6:53",
	"101.226.4.6:53", "180.76.76.76:53",
}

type DNSProxy struct {
	UpstreamDNS     string
	FallbackServers []string

	activeResolver string
	mu             sync.RWMutex
}

func NewDNSProxy(upstreamDNS string) *DNSProxy {
	return &DNSProxy{
		UpstreamDNS:     fmt.Sprintf("%s:53", upstreamDNS),
		FallbackServers: defaultFallbackServers,
		activeResolver:  fmt.Sprintf("%s:53", upstreamDNS),
	}
}

func RunDNSProxy(upstreamDNS string) error {
	proxy := NewDNSProxy(upstreamDNS)
	return proxy.Run()
}

func (p *DNSProxy) Run() error {
	addr := net.UDPAddr{
		Port: 53,
		IP:   net.ParseIP("127.0.0.1"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return err
	}
	logging.Debug("Starting DNS Proxy on 127.0.0.1:53 forwarding to %s", p.UpstreamDNS)
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		reqData := make([]byte, n)
		copy(reqData, buf[:n])

		go p.handleDNSQuery(conn, clientAddr, reqData)
	}
}

func (p *DNSProxy) handleDNSQuery(clientConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	p.mu.RLock()
	resolver := p.activeResolver
	p.mu.RUnlock()

	allResolvers := []string{p.UpstreamDNS}
	for _, b := range p.FallbackServers {
		if b != p.UpstreamDNS {
			allResolvers = append(allResolvers, b)
		}
	}

	startIdx := 0
	for idx, addr := range allResolvers {
		if addr == resolver {
			startIdx = idx
			break
		}
	}

	for k := 0; k < len(allResolvers); k++ {
		idx := (startIdx + k) % len(allResolvers)
		addr := allResolvers[idx]

		respData, err := p.exchangeDNS(data, addr)
		if err == nil {
			if idx != startIdx {
				p.mu.Lock()
				p.activeResolver = addr
				p.mu.Unlock()
				logging.Info("DNS failover: resolver %s failed, using fallback %s", resolver, addr)
			}
			clientConn.WriteToUDP(respData, clientAddr)
			return
		}
		logging.Debug("DNS query to %s failed: %v", addr, err)
	}

	logging.Error("DNS query failed for all upstream servers (started at: %s)", resolver)
}

func (p *DNSProxy) exchangeDNS(data []byte, upstreamAddr string) ([]byte, error) {
	tcpData := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(tcpData[0:2], uint16(len(data)))
	copy(tcpData[2:], data)

	tcpConn, err := net.DialTimeout("tcp", upstreamAddr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer tcpConn.Close()
	tcpConn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := tcpConn.Write(tcpData); err != nil {
		return nil, err
	}

	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, respLenBuf); err != nil {
		return nil, err
	}

	respLen := binary.BigEndian.Uint16(respLenBuf)
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(tcpConn, respData); err != nil {
		return nil, err
	}

	return respData, nil
}
