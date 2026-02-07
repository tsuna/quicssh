package main

import (
	"container/list"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ChaosConfig controls the chaos injection behavior.
type ChaosConfig struct {
	// Packet loss probability (0.0 to 1.0)
	DropRate float64
	// Packet reordering probability (0.0 to 1.0)
	ReorderRate float64
	// Maximum delay for reordered packets
	MaxReorderDelay time.Duration
	// Packet duplication probability (0.0 to 1.0)
	DuplicateRate float64
	// Random number generator (for reproducibility)
	Rand *rand.Rand
}

// ChaosPacketConn wraps a FakePacketConn and injects random faults.
type ChaosPacketConn struct {
	*FakePacketConn

	mu     sync.Mutex
	config ChaosConfig

	// Reorder queue: packets waiting to be delivered out of order
	reorderQueue *list.List
	reorderTimer *time.Timer

	// Stats
	packetsDropped    atomic.Uint64
	packetsReordered  atomic.Uint64
	packetsDuplicated atomic.Uint64
}

// reorderedPacket represents a packet waiting to be delivered.
type reorderedPacket struct {
	data      []byte
	addr      net.Addr
	deliverAt time.Time
}

// NewChaosPacketConn wraps a FakePacketConn with chaos injection.
func NewChaosPacketConn(conn *FakePacketConn, config ChaosConfig) *ChaosPacketConn {
	c := &ChaosPacketConn{
		FakePacketConn: conn,
		config:         config,
		reorderQueue:   list.New(),
	}
	return c
}

// WriteTo intercepts writes and may drop, reorder, or duplicate packets.
func (c *ChaosPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we should drop this packet
	if c.config.Rand.Float64() < c.config.DropRate {
		c.packetsDropped.Add(1)
		// Pretend we sent it successfully
		return len(p), nil
	}

	// Check if we should duplicate this packet
	if c.config.Rand.Float64() < c.config.DuplicateRate {
		c.packetsDuplicated.Add(1)
		// Send the original
		if _, err := c.FakePacketConn.WriteTo(p, addr); err != nil {
			return 0, err
		}
		// Send the duplicate (may also be subject to drop/reorder)
		// Fall through to normal send logic
	}

	// Check if we should reorder this packet
	if c.config.Rand.Float64() < c.config.ReorderRate && c.config.MaxReorderDelay > 0 {
		c.packetsReordered.Add(1)
		// Add to reorder queue with random delay
		delay := time.Duration(c.config.Rand.Int63n(int64(c.config.MaxReorderDelay)))
		// Make a copy of the data
		data := make([]byte, len(p))
		copy(data, p)
		c.reorderQueue.PushBack(&reorderedPacket{
			data:      data,
			addr:      addr,
			deliverAt: time.Now().Add(delay),
		})
		// Schedule delivery
		c.scheduleReorderDelivery()
		return len(p), nil
	}

	// Send normally
	return c.FakePacketConn.WriteTo(p, addr)
}

// scheduleReorderDelivery schedules a timer to deliver reordered packets.
// Must be called with c.mu held.
func (c *ChaosPacketConn) scheduleReorderDelivery() {
	if c.reorderQueue.Len() == 0 {
		return
	}

	// Find the earliest packet to deliver
	var earliest time.Time
	for e := c.reorderQueue.Front(); e != nil; e = e.Next() {
		pkt := e.Value.(*reorderedPacket)
		if earliest.IsZero() || pkt.deliverAt.Before(earliest) {
			earliest = pkt.deliverAt
		}
	}

	// Cancel existing timer
	if c.reorderTimer != nil {
		c.reorderTimer.Stop()
	}

	// Schedule new timer
	delay := time.Until(earliest)
	if delay < 0 {
		delay = 0
	}
	c.reorderTimer = time.AfterFunc(delay, func() {
		c.deliverReorderedPackets()
	})
}

// deliverReorderedPackets delivers any packets whose time has come.
func (c *ChaosPacketConn) deliverReorderedPackets() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var next *list.Element
	for e := c.reorderQueue.Front(); e != nil; e = next {
		next = e.Next()
		pkt := e.Value.(*reorderedPacket)
		if pkt.deliverAt.Before(now) || pkt.deliverAt.Equal(now) {
			// Deliver this packet
			c.FakePacketConn.WriteTo(pkt.data, pkt.addr)
			c.reorderQueue.Remove(e)
		}
	}

	// Schedule next delivery if needed
	c.scheduleReorderDelivery()
}

// GetStats returns chaos injection statistics.
func (c *ChaosPacketConn) GetStats() (dropped, reordered, duplicated uint64) {
	return c.packetsDropped.Load(), c.packetsReordered.Load(), c.packetsDuplicated.Load()
}

// Close cleans up resources.
func (c *ChaosPacketConn) Close() error {
	c.mu.Lock()
	if c.reorderTimer != nil {
		c.reorderTimer.Stop()
	}
	c.mu.Unlock()
	return c.FakePacketConn.Close()
}

// NewChaosPacketConnPair creates a pair of ChaosPacketConns for testing.
func NewChaosPacketConnPair(bufferSize int, config1, config2 ChaosConfig) (*ChaosPacketConn, *ChaosPacketConn) {
	conn1, conn2 := NewFakePacketConnPair(bufferSize)
	chaos1 := NewChaosPacketConn(conn1, config1)
	chaos2 := NewChaosPacketConn(conn2, config2)
	return chaos1, chaos2
}
