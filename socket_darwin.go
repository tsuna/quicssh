//go:build darwin

package main

import (
	"net"
)

// configureUDPSocket configures the UDP socket to be more resilient to
// network hiccups. On Darwin (macOS), ICMP errors are not delivered to
// UDP sockets by default, so no special configuration is needed.
func configureUDPSocket(conn *net.UDPConn) error {
	// On macOS, ICMP errors are not passed to UDP sockets by default,
	// so no special configuration is needed for resilience.
	return nil
}

