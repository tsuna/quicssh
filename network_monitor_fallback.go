//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package main

import (
	"context"
	"log"
	"net"
	"time"
)

// NetworkMonitor monitors network interface changes using polling (fallback for Windows and other platforms)
type NetworkMonitor struct {
	events     chan NetworkEvent
	done       chan struct{}
	interfaces map[string][]string // interface -> addresses
	verbose    bool
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor(verbose bool) *NetworkMonitor {
	return &NetworkMonitor{
		events:     make(chan NetworkEvent, 10),
		done:       make(chan struct{}),
		interfaces: make(map[string][]string),
		verbose:    verbose,
	}
}

// Start begins monitoring network interface changes using polling
func (nm *NetworkMonitor) Start(ctx context.Context) error {
	if nm.verbose {
		log.Printf("Using fallback network monitoring (polling) - event-based monitoring not available on this platform")
	}
	
	// Initialize current state
	if err := nm.updateInterfaceState(); err != nil {
		return err
	}

	go func() {
		defer close(nm.events)
		ticker := time.NewTicker(5 * time.Second) // Poll every 5 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-nm.done:
				return
			case <-ticker.C:
				nm.checkForChanges()
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

// updateInterfaceState updates the current interface state
func (nm *NetworkMonitor) updateInterfaceState() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	newState := make(map[string][]string)
	
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // Skip down interfaces
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var addresses []string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				addresses = append(addresses, ipnet.IP.String())
			}
		}
		
		newState[iface.Name] = addresses
	}

	nm.interfaces = newState
	return nil
}

// checkForChanges compares current state with previous state and generates events
func (nm *NetworkMonitor) checkForChanges() {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	newState := make(map[string][]string)
	
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var addresses []string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				addresses = append(addresses, ipnet.IP.String())
			}
		}

		// Check if interface went up or down
		wasUp := len(nm.interfaces[iface.Name]) > 0
		isUp := (iface.Flags&net.FlagUp != 0) && len(addresses) > 0
		
		if !wasUp && isUp {
			nm.sendEvent(NetworkEvent{
				Type:      "link_up",
				Interface: iface.Name,
			})
		} else if wasUp && !isUp {
			nm.sendEvent(NetworkEvent{
				Type:      "link_down", 
				Interface: iface.Name,
			})
		}

		if isUp {
			newState[iface.Name] = addresses
		}
	}

	nm.interfaces = newState
}

// sendEvent sends an event to the events channel
func (nm *NetworkMonitor) sendEvent(event NetworkEvent) {
	select {
	case nm.events <- event:
		if nm.verbose {
			log.Printf("Network event: %s interface %s", event.Type, event.Interface)
		}
	default:
		// Channel full, drop event
	}
}
