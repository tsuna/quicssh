//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"context"
	"log"
	"net"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// NetworkMonitor monitors network interface changes using BSD routing socket
type NetworkMonitor struct {
	events  chan NetworkEvent
	done    chan struct{}
	fd      int  // routing socket file descriptor
	verbose bool // whether to log events
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor(verbose bool) *NetworkMonitor {
	return &NetworkMonitor{
		events:  make(chan NetworkEvent, 10),
		done:    make(chan struct{}),
		fd:      -1,
		verbose: verbose,
	}
}

// Start begins monitoring network interface changes using BSD routing socket
func (nm *NetworkMonitor) Start(ctx context.Context) error {
	if nm.verbose {
		log.Printf("Using BSD routing socket for event-based network monitoring")
	}

	// Open a routing socket to receive network change notifications
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	nm.fd = fd

	go nm.readRoutingMessages(ctx)

	return nil
}

// Events returns the channel for receiving network events
func (nm *NetworkMonitor) Events() <-chan NetworkEvent {
	return nm.events
}

// Stop stops the network monitor
func (nm *NetworkMonitor) Stop() {
	close(nm.done)
	if nm.fd >= 0 {
		unix.Close(nm.fd)
	}
}

// readRoutingMessages reads and processes messages from the routing socket
func (nm *NetworkMonitor) readRoutingMessages(ctx context.Context) {
	defer close(nm.events)

	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return
		case <-nm.done:
			return
		default:
		}

		// Set a read timeout so we can check for context cancellation
		if err := unix.SetsockoptTimeval(nm.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
			if nm.verbose {
				log.Printf("Failed to set socket timeout: %v", err)
			}
			continue
		}

		n, err := unix.Read(nm.fd, buf)
		if err != nil {
			// Timeout is expected, continue to check context
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			// Check if socket was closed
			if err == unix.EBADF {
				return
			}
			continue
		}

		if n > 0 {
			nm.parseRoutingMessage(buf[:n])
		}
	}
}

// parseRoutingMessage parses a routing message and generates events
func (nm *NetworkMonitor) parseRoutingMessage(data []byte) {
	// Try parsing as interface messages first
	msgs, err := route.ParseRIB(route.RIBTypeInterface, data)
	if err != nil {
		// Try parsing as route messages (some address messages may need this)
		msgs, err = route.ParseRIB(route.RIBTypeRoute, data)
		if err != nil {
			if nm.verbose {
				// Log the raw message type for debugging
				if len(data) >= 4 {
					msgType := data[3] // RTM_* type is at offset 3
					log.Printf("Network monitor: unparseable message type=%d len=%d", msgType, len(data))
				}
			}
			return
		}
	}

	for _, msg := range msgs {
		switch m := msg.(type) {
		case *route.InterfaceMessage:
			nm.handleInterfaceMessage(m)
		case *route.InterfaceAddrMessage:
			nm.handleInterfaceAddrMessage(m)
		case *route.InterfaceAnnounceMessage:
			nm.handleInterfaceAnnounceMessage(m)
		case *route.RouteMessage:
			// Route changes can also indicate network changes
			nm.handleRouteMessage(m)
		default:
			if nm.verbose {
				log.Printf("Network monitor: unhandled message type: %T", msg)
			}
		}
	}
}

// handleInterfaceMessage handles interface up/down events
func (nm *NetworkMonitor) handleInterfaceMessage(m *route.InterfaceMessage) {
	ifaceName := m.Name
	if ifaceName == "" {
		ifaceName = nm.getInterfaceName(m.Index)
	}

	// Check interface flags for up/down status
	// RTM_IFINFO messages indicate interface state changes
	if m.Type == syscall.RTM_IFINFO {
		// IFF_UP flag indicates if interface is up
		if m.Flags&syscall.IFF_UP != 0 {
			nm.sendEvent(NetworkEvent{
				Type:      "link_up",
				Interface: ifaceName,
			})
		} else {
			nm.sendEvent(NetworkEvent{
				Type:      "link_down",
				Interface: ifaceName,
			})
		}
	}
}

// handleInterfaceAddrMessage handles address add/remove events
func (nm *NetworkMonitor) handleInterfaceAddrMessage(m *route.InterfaceAddrMessage) {
	ifaceName := nm.getInterfaceName(m.Index)
	var addrStr string

	// Extract the address from the message
	for _, addr := range m.Addrs {
		switch a := addr.(type) {
		case *route.Inet4Addr:
			addrStr = net.IP(a.IP[:]).String()
		case *route.Inet6Addr:
			addrStr = net.IP(a.IP[:]).String()
		}
	}

	switch m.Type {
	case syscall.RTM_NEWADDR:
		nm.sendEvent(NetworkEvent{
			Type:      "addr_add",
			Interface: ifaceName,
			Address:   addrStr,
		})
	case syscall.RTM_DELADDR:
		nm.sendEvent(NetworkEvent{
			Type:      "addr_del",
			Interface: ifaceName,
			Address:   addrStr,
		})
	}
}

// handleInterfaceAnnounceMessage handles interface arrival/departure events
func (nm *NetworkMonitor) handleInterfaceAnnounceMessage(m *route.InterfaceAnnounceMessage) {
	// IFAN_ARRIVAL = 0, IFAN_DEPARTURE = 1
	switch m.What {
	case 0: // IFAN_ARRIVAL
		nm.sendEvent(NetworkEvent{
			Type:      "link_up",
			Interface: m.Name,
		})
	case 1: // IFAN_DEPARTURE
		nm.sendEvent(NetworkEvent{
			Type:      "link_down",
			Interface: m.Name,
		})
	}
}

// handleRouteMessage handles route changes (which may indicate VPN or network changes)
func (nm *NetworkMonitor) handleRouteMessage(m *route.RouteMessage) {
	// Route messages contain RTM_ADD, RTM_DELETE, RTM_CHANGE
	// These can indicate VPN or default route changes
	ifaceName := ""
	if m.Index > 0 {
		ifaceName = nm.getInterfaceName(m.Index)
	}

	switch m.Type {
	case syscall.RTM_ADD:
		if nm.verbose {
			log.Printf("Network monitor: route added (interface index: %d, name: %s)", m.Index, ifaceName)
		}
		if ifaceName != "" {
			nm.sendEvent(NetworkEvent{
				Type:      "route_add",
				Interface: ifaceName,
			})
		}
	case syscall.RTM_DELETE:
		if nm.verbose {
			log.Printf("Network monitor: route deleted (interface index: %d, name: %s)", m.Index, ifaceName)
		}
		if ifaceName != "" {
			nm.sendEvent(NetworkEvent{
				Type:      "route_del",
				Interface: ifaceName,
			})
		}
	case syscall.RTM_LOSING:
		// RTM_LOSING indicates the route is being lost (useful for disconnect detection)
		if nm.verbose {
			log.Printf("Network monitor: route losing (interface index: %d, name: %s)", m.Index, ifaceName)
		}
		if ifaceName != "" {
			nm.sendEvent(NetworkEvent{
				Type:      "link_down",
				Interface: ifaceName,
			})
		}
	}
}

// getInterfaceName looks up interface name by index
func (nm *NetworkMonitor) getInterfaceName(index int) string {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return ""
	}
	return iface.Name
}

// sendEvent sends an event to the events channel
func (nm *NetworkMonitor) sendEvent(event NetworkEvent) {
	select {
	case nm.events <- event:
		if nm.verbose {
			log.Printf("Network event: %s interface %s (addr: %s)", event.Type, event.Interface, event.Address)
		}
	default:
		// Channel full, drop event
	}
}

