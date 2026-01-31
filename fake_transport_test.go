package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Packet represents a UDP packet with source address.
type Packet struct {
	Data []byte
	Addr net.Addr
}

// FakePacketConn implements net.PacketConn for testing.
// It uses channels to simulate UDP communication.
type FakePacketConn struct {
	mu         sync.Mutex
	closed     atomic.Bool
	localAddr  net.Addr
	remoteAddr net.Addr // For connected mode

	// Channels for packet delivery
	recvCh   chan Packet                  // Incoming packets
	sendFunc func([]byte, net.Addr) error // Function to send packets

	// Deadlines
	readDeadline  time.Time
	writeDeadline time.Time
	closeCh       chan struct{} // Closed when connection is closed
}

// NewFakePacketConnPair creates a connected pair of FakePacketConns.
// Packets written to one will be read from the other.
func NewFakePacketConnPair(bufferSize int) (*FakePacketConn, *FakePacketConn) {
	addr1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
	addr2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10002}

	ch1 := make(chan Packet, bufferSize)
	ch2 := make(chan Packet, bufferSize)

	conn1 := &FakePacketConn{
		localAddr:  addr1,
		remoteAddr: addr2,
		recvCh:     ch1,
		closeCh:    make(chan struct{}),
	}

	conn2 := &FakePacketConn{
		localAddr:  addr2,
		remoteAddr: addr1,
		recvCh:     ch2,
		closeCh:    make(chan struct{}),
	}

	// Wire up send functions
	conn1.sendFunc = func(data []byte, addr net.Addr) error {
		if conn2.closed.Load() {
			return errors.New("connection closed")
		}
		pkt := Packet{Data: make([]byte, len(data)), Addr: conn1.localAddr}
		copy(pkt.Data, data)
		select {
		case ch2 <- pkt:
			return nil
		case <-conn2.closeCh:
			return errors.New("connection closed")
		}
	}

	conn2.sendFunc = func(data []byte, addr net.Addr) error {
		if conn1.closed.Load() {
			return errors.New("connection closed")
		}
		pkt := Packet{Data: make([]byte, len(data)), Addr: conn2.localAddr}
		copy(pkt.Data, data)
		select {
		case ch1 <- pkt:
			return nil
		case <-conn1.closeCh:
			return errors.New("connection closed")
		}
	}

	return conn1, conn2
}

// ReadFrom reads a packet from the connection.
func (c *FakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, errors.New("connection closed")
	}

	// Handle deadline
	var timer <-chan time.Time
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()
	if !deadline.IsZero() {
		dur := time.Until(deadline)
		if dur <= 0 {
			return 0, nil, &timeoutError{}
		}
		timer = time.After(dur)
	}

	select {
	case pkt := <-c.recvCh:
		n = copy(p, pkt.Data)
		return n, pkt.Addr, nil
	case <-c.closeCh:
		return 0, nil, errors.New("connection closed")
	case <-timer:
		return 0, nil, &timeoutError{}
	}
}

// WriteTo writes a packet to addr.
func (c *FakePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, errors.New("connection closed")
	}
	if c.sendFunc == nil {
		return 0, errors.New("not connected")
	}
	err = c.sendFunc(p, addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the connection.
func (c *FakePacketConn) Close() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}
	close(c.closeCh)
	return nil
}

// LocalAddr returns the local address.
func (c *FakePacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

// SetDeadline sets both read and write deadlines.
func (c *FakePacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *FakePacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *FakePacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

// timeoutError implements the net.Error interface for timeouts.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// FakeTransporter creates transports using FakePacketConn pairs.
// It implements the Transporter interface for testing.
type FakeTransporter struct {
	mu             sync.Mutex
	connGenerator  func() *FakePacketConn
	generatedConns []*FakePacketConn
	remoteAddr     net.Addr // Fixed remote address for testing
}

// NewFakeTransporter creates a transporter that uses the provided
// function to generate new FakePacketConns.
func NewFakeTransporter(connGenerator func() *FakePacketConn, remoteAddr net.Addr) *FakeTransporter {
	return &FakeTransporter{
		connGenerator: connGenerator,
		remoteAddr:    remoteAddr,
	}
}

// NewTransport creates a new QUIC transport from a fake connection.
func (f *FakeTransporter) NewTransport(ctx context.Context) (*quic.Transport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	conn := f.connGenerator()
	f.generatedConns = append(f.generatedConns, conn)
	return &quic.Transport{Conn: conn}, nil
}

// RemoteAddr returns the fixed remote address for testing.
func (f *FakeTransporter) RemoteAddr(ctx context.Context) (net.Addr, error) {
	return f.remoteAddr, nil
}

// GetGeneratedConns returns all connections created by this transporter.
func (f *FakeTransporter) GetGeneratedConns() []*FakePacketConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.generatedConns
}

// BreakablePacketConn wraps a FakePacketConn and allows breaking/restoring the connection.
type BreakablePacketConn struct {
	*FakePacketConn
	broken atomic.Bool
}

// NewBreakablePacketConn wraps a FakePacketConn with break/restore capability.
func NewBreakablePacketConn(conn *FakePacketConn) *BreakablePacketConn {
	return &BreakablePacketConn{FakePacketConn: conn}
}

// Break simulates a connection break - subsequent reads/writes will fail.
func (c *BreakablePacketConn) Break() {
	c.broken.Store(true)
}

// Restore restores the connection after a break.
func (c *BreakablePacketConn) Restore() {
	c.broken.Store(false)
}

// ReadFrom reads a packet, but fails if connection is broken.
func (c *BreakablePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.broken.Load() {
		return 0, nil, &temporaryError{msg: "connection broken"}
	}
	return c.FakePacketConn.ReadFrom(p)
}

// WriteTo writes a packet, but fails if connection is broken.
func (c *BreakablePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.broken.Load() {
		return 0, &temporaryError{msg: "connection broken"}
	}
	return c.FakePacketConn.WriteTo(p, addr)
}

// temporaryError represents a temporary network error.
type temporaryError struct {
	msg string
}

func (e *temporaryError) Error() string   { return e.msg }
func (e *temporaryError) Timeout() bool   { return false }
func (e *temporaryError) Temporary() bool { return true }
