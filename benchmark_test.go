package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// benchConfig holds parameters for the throughput benchmark.
type benchConfig struct {
	// Chaos parameters (zero values = no chaos)
	dropRate        float64
	reorderRate     float64
	duplicateRate   float64
	disconnectRate  float64
	maxReorderDelay time.Duration

	// Message configuration
	messageSize int // payload size per message
}

// BenchmarkThroughput_NoDisruption measures throughput with a clean channel.
func BenchmarkThroughput_NoDisruption(b *testing.B) {
	runThroughputBenchmark(b, benchConfig{
		messageSize: 40, // same as torture test
	})
}

// BenchmarkThroughput_WithChaos measures throughput with packet drops, reordering,
// and duplication (same parameters as the torture test, but no disconnects).
func BenchmarkThroughput_WithChaos(b *testing.B) {
	runThroughputBenchmark(b, benchConfig{
		dropRate:        0.05,
		reorderRate:     0.10,
		duplicateRate:   0.02,
		maxReorderDelay: 100 * time.Millisecond,
		messageSize:     40,
	})
}

// BenchmarkThroughput_WithDisconnects measures throughput with full chaos
// including random disconnects (same parameters as the torture test).
func BenchmarkThroughput_WithDisconnects(b *testing.B) {
	runThroughputBenchmark(b, benchConfig{
		dropRate:        0.05,
		reorderRate:     0.10,
		duplicateRate:   0.02,
		disconnectRate:  0.01,
		maxReorderDelay: 100 * time.Millisecond,
		messageSize:     40,
	})
}

// BenchmarkThroughput_LargeFrames measures throughput with 32KB frames (no chaos).
func BenchmarkThroughput_LargeFrames(b *testing.B) {
	runThroughputBenchmark(b, benchConfig{
		messageSize: 32 * 1024,
	})
}

// BenchmarkThroughput_LargeFrames_WithChaos measures throughput with 32KB frames and chaos.
func BenchmarkThroughput_LargeFrames_WithChaos(b *testing.B) {
	runThroughputBenchmark(b, benchConfig{
		dropRate:        0.05,
		reorderRate:     0.10,
		duplicateRate:   0.02,
		maxReorderDelay: 100 * time.Millisecond,
		messageSize:     32 * 1024,
	})
}

// benchQuicConfig returns a QUIC config suitable for benchmarks.
// Uses a longer idle timeout than tests to avoid false timeouts during long runs.
func benchQuicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	}
}

func runThroughputBenchmark(b *testing.B, cfg benchConfig) {
	b.Helper()

	// Suppress all log output during benchmarks
	origOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(origOutput)

	quietLogf := func(string, ...interface{}) {}

	// Start echo server as fake sshd
	sshdAddr, cleanupSshd := startBenchEchoServer(b)
	defer cleanupSshd()

	serverTLS, err := generateTestTLSConfig()
	if err != nil {
		b.Fatalf("Failed to generate TLS config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rng := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

	// Create packet connections (with or without chaos)
	var clientConn, serverConn interface {
		net.PacketConn
		GetStats() (uint64, uint64, uint64)
	}
	if cfg.dropRate > 0 || cfg.reorderRate > 0 || cfg.duplicateRate > 0 {
		c, s := NewChaosPacketConnPair(2000,
			ChaosConfig{
				DropRate:        cfg.dropRate,
				ReorderRate:     cfg.reorderRate,
				DuplicateRate:   cfg.duplicateRate,
				MaxReorderDelay: cfg.maxReorderDelay,
				Rand:            mathrand.New(mathrand.NewSource(rng.Int63())),
			},
			ChaosConfig{
				DropRate:        cfg.dropRate,
				ReorderRate:     cfg.reorderRate,
				DuplicateRate:   cfg.duplicateRate,
				MaxReorderDelay: cfg.maxReorderDelay,
				Rand:            mathrand.New(mathrand.NewSource(rng.Int63())),
			},
		)
		clientConn, serverConn = c, s
	} else {
		c, s := NewFakePacketConnPair(2000)
		clientConn, serverConn = &fakeConnWithStats{c}, &fakeConnWithStats{s}
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
		b.Fatalf("Failed to create server: %v", err)
	}
	go server.Serve()

	clientTLS := generateTestClientTLSConfig()
	quicConfig := benchQuicConfig()

	clientSession, err := NewClientSession(DefaultBufferSize, quietLogf)
	if err != nil {
		b.Fatalf("Failed to create client session: %v", err)
	}

	clientTransport := &quic.Transport{Conn: clientConn}

	// Establish initial connection
	quicConn, err := clientTransport.Dial(ctx, serverConn.LocalAddr(), clientTLS, quicConfig)
	if err != nil {
		b.Fatalf("Client dial failed: %v", err)
	}
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("Failed to open stream: %v", err)
	}
	if err := clientSession.Connect(stream); err != nil {
		b.Fatalf("Client session connect failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let server process

	// Tracking
	var (
		clientSentSeq     atomic.Uint64
		clientReceivedSeq atomic.Uint64
		reconnectCount    atomic.Uint64
		totalBytesSent    atomic.Int64
		benchErrors       []string
		benchErrorsMu     sync.Mutex
	)

	recordError := func(format string, args ...interface{}) {
		benchErrorsMu.Lock()
		defer benchErrorsMu.Unlock()
		benchErrors = append(benchErrors, fmt.Sprintf(format, args...))
	}

	b.ResetTimer()
	b.SetBytes(int64(cfg.messageSize))

	// Client goroutine
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)

		clientCtx, clientCancel := context.WithCancel(ctx)
		defer clientCancel()

		isFirstConnection := true
		messagesRemaining := b.N

		for messagesRemaining > 0 {
			// Dial (reuse transport for reconnects)
			if !isFirstConnection {
				dialCtx, dialCancel := context.WithTimeout(clientCtx, 5*time.Second)
				var dialErr error
				quicConn, dialErr = clientTransport.Dial(dialCtx, serverConn.LocalAddr(), clientTLS, quicConfig)
				dialCancel()
				if dialErr != nil {
					if clientCtx.Err() != nil {
						return
					}
					recordError("Client dial failed: %v", dialErr)
					return
				}
				var streamErr error
				stream, streamErr = quicConn.OpenStreamSync(clientCtx)
				if streamErr != nil {
					if clientCtx.Err() != nil {
						return
					}
					recordError("Failed to open stream: %v", streamErr)
					return
				}

				framesToReplay, resumeErr := clientSession.Resume(stream)
				if errors.Is(resumeErr, ErrSessionNotFound) && reconnectCount.Load() == 0 && clientReceivedSeq.Load() == 0 {
					quicConn.CloseWithError(0, "session not found")
					clientSession, _ = NewClientSession(DefaultBufferSize, quietLogf)
					clientSentSeq.Store(0)
					clientReceivedSeq.Store(0)
					isFirstConnection = true
					continue
				}
				if resumeErr != nil {
					recordError("Resume failed: %v", resumeErr)
					return
				}
				encBuf := clientSession.EncodeBuffer()
				for _, frame := range framesToReplay {
					if err := frame.Encode(stream, encBuf); err != nil {
						recordError("Replay failed: %v", err)
						return
					}
				}
				reconnectCount.Add(1)
			}
			isFirstConnection = false

			// Receiver goroutine: count echoed bytes and handle ACKs.
			// We don't validate message ordering here — the echo server
			// returns a byte stream that doesn't preserve message boundaries
			// for large frames. Ordering is validated by the torture test.
			receiveDone := make(chan struct{})
			go func() {
				defer close(receiveDone)
				for {
					frame, err := ReadFrame(stream, nil)
					if err != nil {
						return
					}
					switch f := frame.(type) {
					case *DataFrame:
						isNew, err := clientSession.HandleData(f)
						if err != nil || !isNew {
							continue
						}
						// Check for poison pill in first 8 bytes
						if len(f.Payload) >= 8 && binary.BigEndian.Uint64(f.Payload[:8]) == 0xFFFFFFFFFFFFFFFF {
							return
						}
						clientReceivedSeq.Add(1)
						_ = clientSession.SendAck()
					case *AckFrame:
						clientSession.HandleAck(f)
					}
				}
			}()

			// Send messages
			shouldDisconnect := false
			for messagesRemaining > 0 {
				seq := clientSentSeq.Add(1) - 1
				payload := make([]byte, cfg.messageSize)
				binary.BigEndian.PutUint64(payload[:8], seq)

				if err := clientSession.SendData(clientCtx, payload); err != nil {
					log.Printf("SendData error: %v", err)
					break
				}
				totalBytesSent.Add(int64(cfg.messageSize))
				messagesRemaining--

				if cfg.disconnectRate > 0 && rng.Float64() < cfg.disconnectRate {
					shouldDisconnect = true
					break
				}
			}

			if messagesRemaining <= 0 {
				// Done — send poison pill
				poisonPill := make([]byte, cfg.messageSize)
				binary.BigEndian.PutUint64(poisonPill[:8], 0xFFFFFFFFFFFFFFFF)
				clientSession.SendData(clientCtx, poisonPill)
				clientSession.Disconnect()
				clientCancel()
				stream.CancelRead(0)
				select {
				case <-receiveDone:
				case <-time.After(2 * time.Second):
				}
				return
			}

			if shouldDisconnect {
				clientSession.Disconnect()
				quicConn.CloseWithError(1, "bench disconnect")
				select {
				case <-receiveDone:
				case <-time.After(2 * time.Second):
				}
				continue
			}
		}
	}()

	<-clientDone
	b.StopTimer()

	cancel()
	clientConn.Close()
	serverConn.Close()
	cleanupSshd()
	server.Close()

	// Report results
	sent := clientSentSeq.Load()
	received := clientReceivedSeq.Load()
	reconnects := reconnectCount.Load()
	bytes := totalBytesSent.Load()

	b.ReportMetric(float64(bytes)/1024/1024, "MB_sent")
	b.ReportMetric(float64(sent), "msgs_sent")
	b.ReportMetric(float64(received), "frames_echoed")
	if reconnects > 0 {
		b.ReportMetric(float64(reconnects), "reconnects")
	}

	benchErrorsMu.Lock()
	if len(benchErrors) > 0 {
		for _, e := range benchErrors {
			b.Errorf("  - %s", e)
		}
	}
	benchErrorsMu.Unlock()
}

// fakeConnWithStats wraps FakePacketConn to implement the GetStats interface.
type fakeConnWithStats struct {
	*FakePacketConn
}

func (f *fakeConnWithStats) GetStats() (uint64, uint64, uint64) {
	return 0, 0, 0
}

// startBenchEchoServer is like startEchoServer but uses b.Helper/b.Fatalf.
func startBenchEchoServer(b *testing.B) (string, func()) {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to start echo server: %v", err)
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
				io.Copy(c, c)
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
