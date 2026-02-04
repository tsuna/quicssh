package main

// NetworkEvent represents a network interface change event.
// Used by platform-specific NetworkMonitor implementations to notify
// the client of network state changes.
type NetworkEvent struct {
	Type      string // "link_up", "link_down", "addr_add", "addr_del", "route_add", "route_del"
	Interface string
	Address   string // for address events
}
