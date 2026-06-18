package proxy

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestHandleDNSQuery(t *testing.T) {
	// Start mock TCP upstream
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		conn.Read(lenBuf)
		reqLen := binary.BigEndian.Uint16(lenBuf)

		reqData := make([]byte, reqLen)
		conn.Read(reqData)

		respData := []byte("dns_mock_response")
		respLenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(respLenBuf, uint16(len(respData)))

		conn.Write(respLenBuf)
		conn.Write(respData)
	}()

	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to bind udp: %v", err)
	}
	defer udpConn.Close()

	p := NewDNSProxy(listener.Addr().String())
	// Strip the :53 added by NewDNSProxy since it's mock
	p.UpstreamDNS = listener.Addr().String()
	p.activeResolver = p.UpstreamDNS

	p.handleDNSQuery(udpConn, udpConn.LocalAddr().(*net.UDPAddr), []byte("query"))

	udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 1024)
	n, _, err := udpConn.ReadFromUDP(resp)
	if err != nil {
		t.Fatalf("failed to read udp response: %v", err)
	}

	if string(resp[:n]) != "dns_mock_response" {
		t.Errorf("got %q, want dns_mock_response", string(resp[:n]))
	}
}

func TestHandleDNSQueryFallback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		conn.Read(lenBuf)
		reqLen := binary.BigEndian.Uint16(lenBuf)

		reqData := make([]byte, reqLen)
		conn.Read(reqData)

		respData := []byte("dns_fallback_response")
		respLenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(respLenBuf, uint16(len(respData)))

		conn.Write(respLenBuf)
		conn.Write(respData)
	}()

	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to bind udp: %v", err)
	}
	defer udpConn.Close()

	p := NewDNSProxy("127.0.0.1")
	p.UpstreamDNS = "127.0.0.1:9999"
	p.activeResolver = p.UpstreamDNS
	p.FallbackServers = []string{listener.Addr().String()}

	p.handleDNSQuery(udpConn, udpConn.LocalAddr().(*net.UDPAddr), []byte("query"))

	udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 1024)
	n, _, err := udpConn.ReadFromUDP(resp)
	if err != nil {
		t.Fatalf("failed to read udp response: %v", err)
	}

	if string(resp[:n]) != "dns_fallback_response" {
		t.Errorf("got %q, want dns_fallback_response", string(resp[:n]))
	}

	p.mu.RLock()
	cached := p.activeResolver
	p.mu.RUnlock()
	if cached != listener.Addr().String() {
		t.Errorf("expected cached resolver to be %s, got %s", listener.Addr().String(), cached)
	}
}
