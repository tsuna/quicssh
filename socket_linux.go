//go:build linux

package main

import (
	"net"
	"syscall"
)

// configureUDPSocket configures the UDP socket to be more resilient to
// network hiccups. On Linux, this disables IP_RECVERR which prevents
// ICMP destination unreachable messages from being delivered to the socket
// and causing read errors. This is important for QUIC connections that
// need to survive temporary network outages (e.g., VPN reconnects).
func configureUDPSocket(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var setsockoptErr error
	err = rawConn.Control(func(fd uintptr) {
		// Disable IP_RECVERR (value 11) to ignore ICMP errors
		// This prevents "destination unreachable" from breaking the connection
		setsockoptErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVERR, 0)
		if setsockoptErr != nil {
			return
		}
		// Also disable for IPv6 if applicable
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR, 0)
	})
	if err != nil {
		return err
	}
	return setsockoptErr
}

