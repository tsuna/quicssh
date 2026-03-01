package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// TestBulkDownload_NoLatency measures throughput with zero network latency
// (in-process FakePacketConn). This establishes the upper bound.
func TestBulkDownload_NoLatency(t *testing.T) {
	runBulkDownloadTest(t, bulkDownloadConfig{
		totalBytes: 100 * 1024 * 1024, // 100MB
	})
}

// TestBulkDownload_160msRTT measures throughput with simulated 160ms RTT,
// matching the real-world VPN/WAN scenario that showed ~62 KB/s.
// Uses 10MB to keep test time reasonable (~5 min at expected ~60 KB/s).
func TestBulkDownload_160msRTT(t *testing.T) {
	runBulkDownloadTest(t, bulkDownloadConfig{
		totalBytes:    10 * 1024 * 1024, // 10MB
		oneWayLatency: 80 * time.Millisecond,
	})
}

// TestBulkDownload_20msRTT measures throughput with 20ms RTT (typical LAN/nearby DC).
func TestBulkDownload_20msRTT(t *testing.T) {
	runBulkDownloadTest(t, bulkDownloadConfig{
		totalBytes:    10 * 1024 * 1024, // 10MB
		oneWayLatency: 10 * time.Millisecond,
	})
}

// TestBulkDownload_50msRTT measures throughput with 50ms RTT (medium distance).
func TestBulkDownload_50msRTT(t *testing.T) {
	runBulkDownloadTest(t, bulkDownloadConfig{
		totalBytes:    10 * 1024 * 1024, // 10MB
		oneWayLatency: 25 * time.Millisecond,
	})
}

type bulkDownloadConfig struct {
	totalBytes    int
	oneWayLatency time.Duration // zero = no artificial latency
}

func runBulkDownloadTest(t *testing.T, cfg bulkDownloadConfig) {
	t.Helper()

	// Suppress log output
	origOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(origOutput)

	quietLogf := func(string, ...interface{}) {}

	// Start data source server
	sshdAddr, cleanupSshd := startDataSourceServerT(t, cfg.totalBytes)
	defer cleanupSshd()

	serverTLS, err := generateTestTLSConfig()
	if err != nil {
		t.Fatalf("Failed to generate TLS config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create packet connections — with or without latency
	var clientConn, serverConn net.PacketConn
	if cfg.oneWayLatency > 0 {
		clientConn, serverConn = newLatencyPacketConnPair(2000, cfg.oneWayLatency)
	} else {
		c, s := NewFakePacketConnPair(2000)
		clientConn, serverConn = c, s
	}
	defer clientConn.Close()
	defer serverConn.Close()

	// Create server
	serverTransport := &quic.Transport{Conn: serverConn}
	server, err := NewTestServer(ctx, serverTransport, &TestServerConfig{
		TLSConfig:           serverTLS,
		QUICConfig:          benchQuicConfig(),
		SSHDAddr:            sshdAddr,
		SessionLayerEnabled: true,
		SessionTimeout:      5 * time.Minute,
		BufferSize:          DefaultBufferSize,
		Logf:                quietLogf,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	go server.Serve()

	// Create client
	clientTLS := generateTestClientTLSConfig()
	clientTransport := &quic.Transport{Conn: clientConn}

	clientSession, err := NewClientSession(DefaultBufferSize, quietLogf)
	if err != nil {
		t.Fatalf("Failed to create client session: %v", err)
	}

	// Establish connection
	quicConn, err := clientTransport.Dial(ctx, serverConn.LocalAddr(), clientTLS, benchQuicConfig())
	if err != nil {
		t.Fatalf("Client dial failed: %v", err)
	}
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	if err := clientSession.Connect(stream); err != nil {
		t.Fatalf("Client session connect failed: %v", err)
	}
	// Wait for server to process NEW_SESSION (longer for high latency)
	time.Sleep(max(50*time.Millisecond, 2*cfg.oneWayLatency+50*time.Millisecond))

	// Read all data from the session layer
	var totalReceived int64
	start := time.Now()
	lastReport := start

	for {
		frame, err := ReadFrame(stream, nil)
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}

		switch f := frame.(type) {
		case *DataFrame:
			isNew, handleErr := clientSession.HandleData(f)
			if handleErr != nil {
				t.Fatalf("HandleData error: %v", handleErr)
			}
			if isNew {
				totalReceived += int64(len(f.Payload))
			}
			go clientSession.SendAck() //nolint:errcheck
		case *AckFrame:
			clientSession.HandleAck(f)
		case *CloseFrame:
			goto done
		default:
			t.Fatalf("Unexpected frame type: %T", f)
		}

		// Periodic progress report
		if now := time.Now(); now.Sub(lastReport) > 2*time.Second {
			elapsed := now.Sub(start)
			pct := float64(totalReceived) / float64(cfg.totalBytes) * 100
			mbps := float64(totalReceived) / 1024 / 1024 / elapsed.Seconds()
			t.Logf("Progress: %.1f%% (%d/%d bytes) in %v — %.2f MB/s",
				pct, totalReceived, cfg.totalBytes, elapsed.Round(time.Millisecond), mbps)
			lastReport = now
		}
	}
done:
	elapsed := time.Since(start)

	throughputMBps := float64(totalReceived) / 1024 / 1024 / elapsed.Seconds()
	t.Logf("Transfer complete: %d bytes in %v — %.2f MB/s (RTT=%v)",
		totalReceived, elapsed.Round(time.Millisecond), throughputMBps, 2*cfg.oneWayLatency)

	if totalReceived < int64(cfg.totalBytes) {
		t.Errorf("Incomplete transfer: got %d/%d bytes (%.1f%%)",
			totalReceived, cfg.totalBytes, float64(totalReceived)/float64(cfg.totalBytes)*100)
	}

	// Report QUIC stats if available
	stats := quicConn.ConnectionStats()
	t.Logf("QUIC Stats: RTT=%v (min=%v), sent=%d pkts/%d bytes, recv=%d pkts/%d bytes, lost=%d pkts",
		stats.SmoothedRTT.Round(time.Millisecond),
		stats.MinRTT.Round(time.Millisecond),
		stats.PacketsSent, stats.BytesSent,
		stats.PacketsReceived, stats.BytesReceived,
		stats.PacketsLost)

	// Clean shutdown
	cancel()
	clientConn.Close()
	serverConn.Close()
	cleanupSshd()
	server.Close()
}

// delayedPacket is a packet waiting for delivery at a specific time.
type delayedPacket struct {
	data      []byte
	addr      net.Addr
	deliverAt time.Time
}

// delayQueue delivers packets in FIFO order after a fixed delay.
// Unlike per-packet goroutines with time.Sleep, a single goroutine processes
// all packets sequentially, preventing reordering from goroutine scheduling
// jitter that causes spurious QUIC loss detections.
type delayQueue struct {
	ch       chan delayedPacket
	sendFunc func([]byte, net.Addr) error
	done     chan struct{}
	once     sync.Once
}

func newDelayQueue(sendFunc func([]byte, net.Addr) error) *delayQueue {
	dq := &delayQueue{
		ch:       make(chan delayedPacket, 8192),
		sendFunc: sendFunc,
		done:     make(chan struct{}),
	}
	go dq.run()
	return dq
}

func (dq *delayQueue) run() {
	defer close(dq.done)
	for pkt := range dq.ch {
		now := time.Now()
		if delay := pkt.deliverAt.Sub(now); delay > 0 {
			time.Sleep(delay)
		}
		dq.sendFunc(pkt.data, pkt.addr) //nolint:errcheck
	}
}

func (dq *delayQueue) close() {
	dq.once.Do(func() {
		close(dq.ch)
	})
	<-dq.done
}

// latencyPacketConn wraps a FakePacketConn and adds one-way latency to
// all outgoing packets. Packets are delivered to the peer after the delay
// using a FIFO delay queue (single goroutine) to prevent reordering.
type latencyPacketConn struct {
	*FakePacketConn
	latency time.Duration
	queue   *delayQueue
	closed  atomic.Bool
}

// newLatencyPacketConnPair creates a pair of packet connections with simulated
// one-way latency in each direction. Total RTT = 2 * oneWayLatency.
func newLatencyPacketConnPair(bufferSize int, oneWayLatency time.Duration) (*latencyPacketConn, *latencyPacketConn) {
	conn1, conn2 := NewFakePacketConnPair(bufferSize)

	origSend1 := conn1.sendFunc
	origSend2 := conn2.sendFunc

	lc1 := &latencyPacketConn{
		FakePacketConn: conn1,
		latency:        oneWayLatency,
		queue:          newDelayQueue(origSend1),
	}
	lc2 := &latencyPacketConn{
		FakePacketConn: conn2,
		latency:        oneWayLatency,
		queue:          newDelayQueue(origSend2),
	}

	// Replace sendFuncs to enqueue with delay instead of delivering immediately.
	conn1.sendFunc = func(data []byte, addr net.Addr) error {
		if lc1.closed.Load() {
			return net.ErrClosed
		}
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		select {
		case lc1.queue.ch <- delayedPacket{data: dataCopy, addr: addr, deliverAt: time.Now().Add(oneWayLatency)}:
			return nil
		default:
			return net.ErrClosed // Queue full, treat as drop
		}
	}

	conn2.sendFunc = func(data []byte, addr net.Addr) error {
		if lc2.closed.Load() {
			return net.ErrClosed
		}
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		select {
		case lc2.queue.ch <- delayedPacket{data: dataCopy, addr: addr, deliverAt: time.Now().Add(oneWayLatency)}:
			return nil
		default:
			return net.ErrClosed
		}
	}

	return lc1, lc2
}

func (c *latencyPacketConn) Close() error {
	c.closed.Store(true)
	c.queue.close()
	return c.FakePacketConn.Close()
}

// startDataSourceServerT starts a TCP server that sends exactly totalBytes
// of random data to each connecting client, then closes. This simulates
// `cat <100MB file>` as the "sshd" process.
func startDataSourceServerT(t *testing.T, totalBytes int) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start data source server: %v", err)
	}

	// Pre-generate the data
	data := make([]byte, totalBytes)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	var connsMu sync.Mutex
	var conns []net.Conn

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				go io.Copy(io.Discard, c)
				written, err := c.Write(data)
				if err != nil {
					fmt.Printf("data source write error after %d/%d bytes: %v\n", written, totalBytes, err)
				}
			}(conn)
		}
	}()

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			close(done)
			listener.Close()
			connsMu.Lock()
			for _, c := range conns {
				c.Close()
			}
			connsMu.Unlock()
			wg.Wait()
		})
	}

	return listener.Addr().String(), cleanup
}

// --- Raw QUIC diagnostic tests (no session layer) ---

// TestRawQUIC_SingleLargeWrite_20msRTT writes 10MB in a single stream.Write().
func TestRawQUIC_SingleLargeWrite_20msRTT(t *testing.T) {
	runRawQUICTest(t, 10*1024*1024, 10*time.Millisecond, false)
}

// TestRawQUIC_SequentialSmallWrites_20msRTT writes 10MB as sequential 32KB writes.
func TestRawQUIC_SequentialSmallWrites_20msRTT(t *testing.T) {
	runRawQUICTest(t, 10*1024*1024, 10*time.Millisecond, true)
}

func runRawQUICTest(t *testing.T, totalBytes int, oneWayLatency time.Duration, smallWrites bool) {
	t.Helper()

	serverTLS, err := generateTestTLSConfig()
	if err != nil {
		t.Fatalf("TLS config: %v", err)
	}
	clientTLS := generateTestClientTLSConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	clientConn, serverConn := newLatencyPacketConnPair(2000, oneWayLatency)
	defer clientConn.Close()
	defer serverConn.Close()

	serverTransport := &quic.Transport{Conn: serverConn}
	listener, err := serverTransport.Listen(serverTLS, benchQuicConfig())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Pre-generate data
	data := make([]byte, totalBytes)
	rand.Read(data)

	// Server: accept connection, accept stream, write data
	type serverResult struct {
		err   error
		stats quic.ConnectionStats
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		// Read trigger byte from client (signals stream is ready)
		var trigger [1]byte
		if _, err := io.ReadFull(stream, trigger[:]); err != nil {
			serverDone <- serverResult{err: fmt.Errorf("read trigger: %w", err)}
			return
		}
		if smallWrites {
			// Sequential 32KB writes (same pattern as sshdToStream)
			buf := data
			for len(buf) > 0 {
				n := 32 * 1024
				if n > len(buf) {
					n = len(buf)
				}
				if _, err := stream.Write(buf[:n]); err != nil {
					serverDone <- serverResult{err: err}
					return
				}
				buf = buf[n:]
			}
		} else {
			// Single large write
			if _, err := stream.Write(data); err != nil {
				serverDone <- serverResult{err: err}
				return
			}
		}
		stream.Close()
		serverDone <- serverResult{stats: conn.ConnectionStats()}
	}()

	// Client: dial, open stream, send trigger, read all data
	clientTransport := &quic.Transport{Conn: clientConn}
	quicConn, err := clientTransport.Dial(ctx, serverConn.LocalAddr(), clientTLS, benchQuicConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// Send trigger byte so server sees the stream via AcceptStream
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatalf("Write trigger: %v", err)
	}

	start := time.Now()
	received, err := io.ReadAll(stream)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(received) != totalBytes {
		t.Fatalf("Got %d bytes, want %d", len(received), totalBytes)
	}

	mode := "single large write"
	if smallWrites {
		mode = "sequential 32KB writes"
	}
	throughput := float64(totalBytes) / 1024 / 1024 / elapsed.Seconds()
	stats := quicConn.ConnectionStats()
	t.Logf("Raw QUIC (%s): %d bytes in %v — %.2f MB/s (RTT=%v, lost=%d pkts)",
		mode, totalBytes, elapsed.Round(time.Millisecond), throughput,
		2*oneWayLatency, stats.PacketsLost)

	srvResult := <-serverDone
	if srvResult.err != nil {
		t.Errorf("Server error: %v", srvResult.err)
	} else {
		ss := srvResult.stats
		t.Logf("Server QUIC Stats: RTT=%v (min=%v), sent=%d pkts/%d bytes, recv=%d pkts/%d bytes, lost=%d pkts",
			ss.SmoothedRTT.Round(time.Millisecond),
			ss.MinRTT.Round(time.Millisecond),
			ss.PacketsSent, ss.BytesSent,
			ss.PacketsReceived, ss.BytesReceived,
			ss.PacketsLost)
	}

	cancel()
	clientConn.Close()
	serverConn.Close()
}
