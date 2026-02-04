//go:build linux

package main

import (
	"context"
	"log"
	"syscall"

	"github.com/vishvananda/netlink"
)

// NetworkMonitor monitors network interface changes using netlink
type NetworkMonitor struct {
	events  chan NetworkEvent
	done    chan struct{}
	verbose bool
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor(verbose bool) *NetworkMonitor {
	return &NetworkMonitor{
		events:  make(chan NetworkEvent, 10),
		done:    make(chan struct{}),
		verbose: verbose,
	}
}

// Start begins monitoring network interface changes
func (nm *NetworkMonitor) Start(ctx context.Context) error {
	// Subscribe to link updates (interface up/down)
	linkUpdates := make(chan netlink.LinkUpdate)
	linkDone := make(chan struct{})
	if err := netlink.LinkSubscribe(linkUpdates, linkDone); err != nil {
		return err
	}

	// Subscribe to address updates (IP address changes)
	addrUpdates := make(chan netlink.AddrUpdate)
	addrDone := make(chan struct{})
	if err := netlink.AddrSubscribe(addrUpdates, addrDone); err != nil {
		close(linkDone)
		return err
	}

	go func() {
		defer close(nm.events)
		defer close(linkDone)
		defer close(addrDone)

		for {
			select {
			case <-ctx.Done():
				return
			case <-nm.done:
				return
			case update := <-linkUpdates:
				nm.handleLinkUpdate(update)
			case update := <-addrUpdates:
				nm.handleAddrUpdate(update)
			}
		}
	}()

	return nil
}

// Events returns the channel for receiving network events
func (nm *NetworkMonitor) Events() <-chan NetworkEvent {
	return nm.events
}

// Stop stops the network monitor
func (nm *NetworkMonitor) Stop() {
	close(nm.done)
}

// handleLinkUpdate processes link (interface) updates
func (nm *NetworkMonitor) handleLinkUpdate(update netlink.LinkUpdate) {
	link := update.Link
	if link == nil {
		return
	}

	var eventType string
	attrs := link.Attrs()
	if attrs == nil {
		return
	}

	// Check if interface went up or down
	switch update.Header.Type {
	case syscall.RTM_NEWLINK:
		if attrs.Flags&syscall.IFF_UP != 0 {
			eventType = "link_up"
		} else {
			eventType = "link_down"
		}
	case syscall.RTM_DELLINK:
		eventType = "link_down"
	default:
		return // Ignore other types
	}

	event := NetworkEvent{
		Type:      eventType,
		Interface: attrs.Name,
	}

	select {
	case nm.events <- event:
		if nm.verbose {
			log.Printf("Network event: %s interface %s", eventType, attrs.Name)
		}
	default:
		// Channel full, drop event
	}
}

// handleAddrUpdate processes address (IP) updates
func (nm *NetworkMonitor) handleAddrUpdate(update netlink.AddrUpdate) {
	if update.LinkAddress.IP == nil {
		return
	}

	var eventType string
	if update.NewAddr {
		eventType = "addr_add"
	} else {
		eventType = "addr_del"
	}

	// Get interface name
	link, err := netlink.LinkByIndex(update.LinkIndex)
	if err != nil {
		return
	}

	event := NetworkEvent{
		Type:      eventType,
		Interface: link.Attrs().Name,
		Address:   update.LinkAddress.IP.String(),
	}

	select {
	case nm.events <- event:
		if nm.verbose {
			log.Printf("Network event: %s address %s on interface %s", eventType, update.LinkAddress.IP.String(), link.Attrs().Name)
		}
	default:
		// Channel full, drop event
	}
}
