//go:build !linux && !darwin

package main

import (
	"net"
)

// configureUDPSocket configures the UDP socket to be more resilient to
// network hiccups. This is a stub for platforms where we don't have
// specific optimizations.
func configureUDPSocket(conn *net.UDPConn) error {
	// No platform-specific configuration available
	return nil
}

