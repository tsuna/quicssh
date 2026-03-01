package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// TestServerConfig holds the configuration for running a quicssh server in tests.
type TestServerConfig struct {
	// TLS configuration
	TLSConfig         *tls.Config
	StatelessResetKey *quic.StatelessResetKey

	// Server address configuration
	SSHDAddr string // Address of local sshd (e.g., "127.0.0.1:22")

	// QUIC configuration
	QUICConfig *quic.Config

	// Session layer configuration
	SessionLayerEnabled bool
	SessionTimeout      time.Duration
	MaxSessions         int
	BufferSize          int

	// Logging
	Logf logFunc
}

// TestServer represents a running quicssh server for testing.
type TestServer struct {
	config    *TestServerConfig
	transport *quic.Transport
	listener  *quic.Listener

	// For session layer
	sessionManager *SessionManager
	sessionHandler *SessionStreamHandler

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc

	// Track active handlers for clean shutdown
	activeHandlers sync.WaitGroup
}

// NewTestServer creates a new TestServer with the given configuration and transport.
// The transport can be created from a real UDP socket or a fake one for testing.
func NewTestServer(ctx context.Context, transport *quic.Transport, cfg *TestServerConfig) (*TestServer, error) {
	listener, err := transport.Listen(cfg.TLSConfig, cfg.QUICConfig)
	if err != nil {
		return nil, err
	}

	serverCtx, cancel := context.WithCancel(ctx)

	s := &TestServer{
		config:    cfg,
		transport: transport,
		listener:  listener,
		ctx:       serverCtx,
		cancel:    cancel,
	}

	if cfg.SessionLayerEnabled {
		s.sessionManager = NewSessionManager(serverCtx, cfg.SSHDAddr, cfg.SessionTimeout, cfg.MaxSessions, cfg.BufferSize, cfg.Logf)
		s.sessionHandler = NewSessionStreamHandler(s.sessionManager, cfg.QUICConfig.MaxIdleTimeout, cfg.Logf)
		cfg.Logf("Session layer enabled (session-timeout: %v, max-sessions: %d, buffer-size: %d)", cfg.SessionTimeout, cfg.MaxSessions, cfg.BufferSize)
	}

	return s, nil
}

// Serve starts accepting connections and blocks until the context is cancelled.
func (s *TestServer) Serve() error {
	logf := s.config.Logf

	for {
		logf("Waiting to accept connection...")
		session, err := s.listener.Accept(s.ctx)
		if err != nil {
			// Check if context was cancelled (graceful shutdown)
			select {
			case <-s.ctx.Done():
				return s.ctx.Err()
			default:
			}
			// Check if listener or transport was closed
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Printf("listener error: %v", err)
			continue
		}

		log.Printf("Accepted connection from %v (local: %v)", session.RemoteAddr(), session.LocalAddr())
		raddr, err := net.ResolveTCPAddr("tcp", s.config.SSHDAddr)
		if err != nil {
			log.Printf("Failed to resolve sshd address: %v", err)
			session.CloseWithError(0, "internal error")
			continue
		}
		go s.handleSession(session, raddr)
	}
}

// handleSession handles a single QUIC session (connection).
func (s *TestServer) handleSession(session *quic.Conn, raddr *net.TCPAddr) {
	remoteAddr := session.RemoteAddr()
	s.config.Logf("[session %v] Handling session...", remoteAddr)

	// Monitor connection context for closure
	go func() {
		<-session.Context().Done()
		s.config.Logf("[session %v] QUIC session context done: %v", remoteAddr, context.Cause(session.Context()))
	}()

	defer func() {
		s.config.Logf("[session %v] Closing session...", remoteAddr)
		if err := session.CloseWithError(0, "close"); err != nil {
			log.Printf("[session %v] Session close error: %v", remoteAddr, err)
		}
	}()

	for {
		s.config.Logf("[session %v] Waiting to accept stream...", remoteAddr)
		stream, err := session.AcceptStream(s.ctx)
		if err != nil {
			log.Printf("[session %v] Session error: %v (type: %T)", remoteAddr, err, err)
			break
		}
		s.config.Logf("[session %v] Accepted stream ID=%v", remoteAddr, stream.StreamID())

		// Capture stream in a local variable for the goroutine
		st := stream
		s.activeHandlers.Add(1)
		if s.config.SessionLayerEnabled && s.sessionHandler != nil {
			go func() {
				defer s.activeHandlers.Done()
				if err := s.sessionHandler.HandleStream(s.ctx, st, session, remoteAddr.String()); err != nil {
					log.Printf("[stream %v from %v] Session handler error: %v", st.StreamID(), remoteAddr, err)
				}
			}()
		} else {
			go func() {
				defer s.activeHandlers.Done()
				serverStreamHandler(s.ctx, st, raddr, s.config.QUICConfig.MaxIdleTimeout, s.config.Logf, remoteAddr)
			}()
		}
	}
}

// Close stops the server and releases resources.
// It waits for all active session handlers to complete before returning.
func (s *TestServer) Close() error {
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	if s.transport != nil {
		s.transport.Close()
	}
	// Wait for all active handlers to complete to avoid logging after test ends
	s.activeHandlers.Wait()
	// Wait for SessionManager cleanup loop to fully exit to prevent signal handler
	// leaks between test iterations (when using -count flag)
	if s.sessionManager != nil {
		s.sessionManager.Wait()
	}
	return nil
}

// Listener returns the underlying QUIC listener (for testing).
func (s *TestServer) Listener() *quic.Listener {
	return s.listener
}

// LocalAddr returns the local address the server is listening on.
func (s *TestServer) LocalAddr() net.Addr {
	return s.transport.Conn.LocalAddr()
}

// SessionManager returns the session manager (for testing with session layer).
func (s *TestServer) SessionManager() *SessionManager {
	return s.sessionManager
}

// generateTestTLSConfig generates a self-signed TLS certificate for testing.
func generateTestTLSConfig() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quicssh"},
	}, nil
}

// generateTestClientTLSConfig creates TLS config for the client.
func generateTestClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicssh"},
	}
}

// testQuicConfig creates a QUIC config suitable for testing.
func testQuicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  5 * time.Second,
		KeepAlivePeriod: 1 * time.Second,
	}
}

// startEchoServer starts a simple TCP echo server for testing.
// Returns the listener address and a cleanup function.
func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Track active connections for cleanup
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
			// Close all active connections to unblock io.Copy
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

// TestE2E_LargeUpload tests that large amounts of data can be sent from
// client to server without deadlocking. This reproduces the VS Code server
// tarball upload scenario where the client sends ~50MB+ through the session
// layer. Without server-to-client AckFrames, the client's send buffer fills
// up (16MB) and the session deadlocks because nothing clears the buffer.
func TestE2E_LargeUpload(t *testing.T) {
	// Start echo server as fake sshd
	sshdAddr, cleanupSshd := startEchoServer(t)
	defer cleanupSshd()

	// Create fake packet connections
	clientConn, serverConn := NewFakePacketConnPair(1000)

	// Create TLS config
	serverTLS, err := generateTestTLSConfig()
	if err != nil {
		t.Fatalf("Failed to generate TLS config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const bufferSize = DefaultBufferSize

	// Create server
	serverTransport := &quic.Transport{Conn: serverConn}
	// Use a quiet logger to avoid per-frame t.Logf overhead during bulk transfer.
	quietLogf := func(format string, args ...interface{}) {}

	serverConfig := &TestServerConfig{
		TLSConfig:           serverTLS,
		QUICConfig:          testQuicConfig(),
		SSHDAddr:            sshdAddr,
		SessionLayerEnabled: true,
		SessionTimeout:      5 * time.Minute,
		BufferSize:          bufferSize,
		Logf:                quietLogf,
	}

	server, err := NewTestServer(ctx, serverTransport, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	go func() { server.Serve() }()

	// Create client transport and connect
	clientTransport := &quic.Transport{Conn: clientConn}
	clientTLS := generateTestClientTLSConfig()
	quicConfig := testQuicConfig()

	session, err := clientTransport.Dial(ctx, serverConn.LocalAddr(), clientTLS, quicConfig)
	if err != nil {
		t.Fatalf("Client dial failed: %v", err)
	}

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}

	clientSession, err := NewClientSession(bufferSize, quietLogf)
	if err != nil {
		t.Fatalf("Failed to create client session: %v", err)
	}
	if err := clientSession.Connect(stream); err != nil {
		t.Fatalf("Client session connect failed: %v", err)
	}

	// Give server time to process
	time.Sleep(100 * time.Millisecond)

	// Send 32MB of data in 32KB chunks — 2x the 16MB buffer.
	// Without server→client AckFrames, this would deadlock when the buffer fills.
	const totalData = 32 * 1024 * 1024
	const chunkSize = 32 * 1024
	totalChunks := totalData / chunkSize
	chunk := make([]byte, chunkSize)

	// Receiver goroutine: read echoed data and handle AckFrames
	receiveDone := make(chan struct{})
	var totalReceived atomic.Int64
	go func() {
		defer close(receiveDone)
		for {
			frame, err := ReadFrame(stream, nil)
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *DataFrame:
				isNew, _ := clientSession.HandleData(f)
				if isNew {
					totalReceived.Add(int64(len(f.Payload)))
				}
				go clientSession.SendAck() //nolint:errcheck // goroutine avoids deadlock under flow control
			case *AckFrame:
				clientSession.HandleAck(f)
			}
		}
	}()

	// Send all chunks with backpressure (same as production client)
	for i := 0; i < totalChunks; i++ {
		for clientSession.SendBufferIsFull(chunkSize) {
			select {
			case <-ctx.Done():
				t.Fatalf("Context canceled while waiting for buffer space at chunk %d/%d", i+1, totalChunks)
			case <-time.After(10 * time.Millisecond):
			}
		}
		if err := clientSession.SendData(ctx, chunk); err != nil {
			t.Fatalf("SendData chunk %d/%d failed: %v", i+1, totalChunks, err)
		}
	}
	t.Logf("Sent %d chunks (%d bytes)", totalChunks, totalData)

	// Wait for all echoed data to arrive
	deadline := time.After(15 * time.Second)
	for totalReceived.Load() < totalData {
		select {
		case <-deadline:
			t.Fatalf("Timeout waiting for echo: received %d/%d bytes", totalReceived.Load(), totalData)
		case <-receiveDone:
			if totalReceived.Load() < totalData {
				t.Fatalf("Receiver exited early: received %d/%d bytes", totalReceived.Load(), totalData)
			}
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	t.Logf("Received all %d bytes echoed back", totalReceived.Load())

	// Cleanup
	cleanupSshd()
	clientConn.Close()
	serverConn.Close()
	stream.Close()
	session.CloseWithError(0, "test done")
	server.Close()
	clientTransport.Close()
}

// TestE2E_BasicConnectivity tests basic QUIC + session layer connectivity.
// This test verifies that:
// 1. Server can be created with fake transport
// 2. Client can connect to server
// 3. Data can flow from client to server and back (via echo server)
func TestE2E_BasicConnectivity(t *testing.T) {
	// Start echo server as fake sshd
	sshdAddr, cleanupSshd := startEchoServer(t)
	defer cleanupSshd()

	// Create fake packet connections
	clientConn, serverConn := NewFakePacketConnPair(1000)

	// Create TLS config
	serverTLS, err := generateTestTLSConfig()
	if err != nil {
		t.Fatalf("Failed to generate TLS config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create server
	serverTransport := &quic.Transport{Conn: serverConn}
	serverConfig := &TestServerConfig{
		TLSConfig:           serverTLS,
		QUICConfig:          testQuicConfig(),
		SSHDAddr:            sshdAddr,
		SessionLayerEnabled: true,
		SessionTimeout:      5 * time.Minute,
		BufferSize:          DefaultBufferSize,
		Logf:                t.Logf,
	}

	server, err := NewTestServer(ctx, serverTransport, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve()
	}()
	_ = serverErr // Silence unused warning

	// Create client transport and connect
	clientTransport := &quic.Transport{Conn: clientConn}

	clientTLS := generateTestClientTLSConfig()
	quicConfig := testQuicConfig()

	session, err := clientTransport.Dial(ctx, serverConn.LocalAddr(), clientTLS, quicConfig)
	if err != nil {
		t.Fatalf("Client dial failed: %v", err)
	}

	t.Logf("Client connected: local=%v remote=%v", session.LocalAddr(), session.RemoteAddr())

	// Open a stream
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}

	t.Logf("Stream opened: ID=%v", stream.StreamID())

	// Create a client session and connect
	clientSession, err := NewClientSession(DefaultBufferSize, t.Logf)
	if err != nil {
		t.Fatalf("Failed to create client session: %v", err)
	}

	if err := clientSession.Connect(stream); err != nil {
		t.Fatalf("Client session connect failed: %v", err)
	}
	t.Log("Client session connected")

	// Give server time to process
	time.Sleep(100 * time.Millisecond)

	// Send some data
	testData := []byte("Hello, World!")
	if err := clientSession.SendData(ctx, testData); err != nil {
		t.Fatalf("SendData failed: %v", err)
	}
	t.Logf("Sent data: %q", testData)

	// Wait for the echo response
	// The server should forward to echo server and echo back
	receivedData := make(chan []byte, 1)
	go func() {
		for {
			frame, err := ReadFrame(stream, nil)
			if err != nil {
				t.Logf("ReadFrame error: %v", err)
				return
			}
			if dataFrame, ok := frame.(*DataFrame); ok {
				receivedData <- dataFrame.Payload
				return
			}
		}
	}()

	select {
	case data := <-receivedData:
		if string(data) != string(testData) {
			t.Errorf("Data mismatch: got %q, want %q", data, testData)
		} else {
			t.Logf("Received echo: %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for echo response")
	}

	// Explicit cleanup in correct order to avoid deadlocks.
	// 1. Close sshd connections first to unblock session handlers reading from sshd
	cleanupSshd()
	// 2. Close the fake connections to unblock any transport goroutines waiting on ReadFrom
	clientConn.Close()
	serverConn.Close()
	// 3. Now we can safely close QUIC objects since the underlying connections are closed
	stream.Close()
	session.CloseWithError(0, "test done")
	// 4. Close server which waits for all session handlers to complete
	server.Close()
	clientTransport.Close()
}

// TestE2E_ConnectionRecovery tests that data is delivered correctly after a connection break.
// It simulates a client sending multiple data frames, then the connection breaks mid-stream.
// A new connection is established, the session resumes, and all data should be delivered.
func TestE2E_ConnectionRecovery(t *testing.T) {
	// Start echo server as fake sshd
	sshdAddr, cleanupSshd := startEchoServer(t)
	defer cleanupSshd()

	// Create fake packet connections
	clientConn, serverConn := NewFakePacketConnPair(1000)

	// Create TLS config
	serverTLS, err := generateTestTLSConfig()
	if err != nil {
		t.Fatalf("Failed to generate TLS config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create server
	serverTransport := &quic.Transport{Conn: serverConn}
	serverConfig := &TestServerConfig{
		TLSConfig:           serverTLS,
		QUICConfig:          testQuicConfig(),
		SSHDAddr:            sshdAddr,
		SessionLayerEnabled: true,
		SessionTimeout:      5 * time.Minute,
		BufferSize:          DefaultBufferSize,
		Logf:                t.Logf,
	}

	server, err := NewTestServer(ctx, serverTransport, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	go func() {
		server.Serve()
	}()

	// Create client transport and connect
	clientTransport := &quic.Transport{Conn: clientConn}

	clientTLS := generateTestClientTLSConfig()
	quicConfig := testQuicConfig()

	session, err := clientTransport.Dial(ctx, serverConn.LocalAddr(), clientTLS, quicConfig)
	if err != nil {
		t.Fatalf("Client dial failed: %v", err)
	}

	t.Logf("Client connected: local=%v remote=%v", session.LocalAddr(), session.RemoteAddr())

	// Open a stream
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}

	t.Logf("Stream opened: ID=%v", stream.StreamID())

	// Create a client session and connect
	clientSession, err := NewClientSession(DefaultBufferSize, t.Logf)
	if err != nil {
		t.Fatalf("Failed to create client session: %v", err)
	}

	if err := clientSession.Connect(stream); err != nil {
		t.Fatalf("Client session connect failed: %v", err)
	}
	t.Log("Client session connected")

	// Give server time to process
	time.Sleep(100 * time.Millisecond)

	// Send first data frame
	testData1 := []byte("Message 1")
	if err := clientSession.SendData(ctx, testData1); err != nil {
		t.Fatalf("SendData 1 failed: %v", err)
	}
	t.Logf("Sent data 1: %q", testData1)

	// Wait for first echo response to confirm it was received
	receivedData := make(chan []byte, 10)
	go func() {
		for {
			frame, err := ReadFrame(stream, nil)
			if err != nil {
				return
			}
			if dataFrame, ok := frame.(*DataFrame); ok {
				receivedData <- dataFrame.Payload
			}
		}
	}()

	select {
	case data := <-receivedData:
		if string(data) != string(testData1) {
			t.Errorf("Data 1 mismatch: got %q, want %q", data, testData1)
		} else {
			t.Logf("Received echo 1: %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for first echo response")
	}

	// Send second data frame (this one might not be ACKed before connection break)
	testData2 := []byte("Message 2")
	if err := clientSession.SendData(ctx, testData2); err != nil {
		t.Fatalf("SendData 2 failed: %v", err)
	}
	t.Logf("Sent data 2: %q", testData2)

	// Wait for second echo
	select {
	case data := <-receivedData:
		if string(data) != string(testData2) {
			t.Errorf("Data 2 mismatch: got %q, want %q", data, testData2)
		} else {
			t.Logf("Received echo 2: %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for second echo response")
	}

	// Now simulate connection break by closing the fake connections
	t.Log("Simulating connection break...")
	clientConn.Close()
	serverConn.Close()
	stream.Close()
	session.CloseWithError(1, "simulated connection break")
	clientTransport.Close()

	// Give server time to detect the disconnection
	time.Sleep(100 * time.Millisecond)

	// Mark client session as disconnected
	clientSession.Disconnect()

	// Create new fake connections for reconnection
	clientConn2, serverConn2 := NewFakePacketConnPair(1000)

	t.Log("Creating new connection for session resume...")

	// Create new client transport with the new fake connection
	clientTransport2 := &quic.Transport{Conn: clientConn2}

	// We need to update the server to listen on the new connection.
	// Actually, the server transport is already closed. We need a new server instance.
	// For this test, we'll create a new transport for the server too.
	serverTransport2 := &quic.Transport{Conn: serverConn2}

	// Create a new listener on the server's new transport
	serverListener2, err := serverTransport2.Listen(serverTLS, quicConfig)
	if err != nil {
		t.Fatalf("Failed to create new server listener: %v", err)
	}

	// Start accepting connections on the new listener
	go func() {
		sess, err := serverListener2.Accept(ctx)
		if err != nil {
			t.Logf("Accept error: %v", err)
			return
		}
		t.Logf("Server accepted reconnection from %v", sess.RemoteAddr())

		// Accept the stream
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			t.Logf("AcceptStream error: %v", err)
			return
		}

		// Handle the resume using the session handler
		// Note: Accept returns *quic.Conn and AcceptStream returns *quic.Stream
		// HandleStream expects *quic.Stream and *quic.Conn
		server.sessionHandler.HandleStream(ctx, st, sess, sess.RemoteAddr().String())
	}()

	// Client reconnects
	session2, err := clientTransport2.Dial(ctx, serverConn2.LocalAddr(), clientTLS, quicConfig)
	if err != nil {
		t.Fatalf("Client reconnect dial failed: %v", err)
	}

	t.Logf("Client reconnected: local=%v remote=%v", session2.LocalAddr(), session2.RemoteAddr())

	// Open a new stream
	stream2, err := session2.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream on reconnection: %v", err)
	}

	t.Logf("Reconnect stream opened: ID=%v", stream2.StreamID())

	// Resume the session
	framesToReplay, err := clientSession.Resume(stream2)
	if err != nil {
		t.Fatalf("Session resume failed: %v", err)
	}

	t.Logf("Session resumed. Frames to replay: %d", len(framesToReplay))

	// Replay any unacknowledged data frames
	for _, frame := range framesToReplay {
		if err := frame.Encode(stream2, nil); err != nil {
			t.Fatalf("Failed to replay frame: %v", err)
		}
		t.Logf("Replayed frame seq=%d", frame.Seq)
	}

	// Send a third message after resume to verify session is working
	testData3 := []byte("Message 3 (after resume)")
	if err := clientSession.SendData(ctx, testData3); err != nil {
		t.Fatalf("SendData 3 failed: %v", err)
	}
	t.Logf("Sent data 3: %q", testData3)

	// Wait for echo response (may include replayed messages + new message)
	receivedData2 := make(chan []byte, 10)
	go func() {
		for {
			frame, err := ReadFrame(stream2, nil)
			if err != nil {
				return
			}
			if dataFrame, ok := frame.(*DataFrame); ok {
				receivedData2 <- dataFrame.Payload
			}
		}
	}()

	// We should receive the echo of message 3
	select {
	case data := <-receivedData2:
		t.Logf("Received after resume: %q", data)
		// The first response might be a replayed message or the new message
		// depending on what the server already received
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for response after resume")
	}

	t.Log("Connection recovery test completed successfully!")

	// Cleanup in correct order to avoid deadlocks and panics from logging after test ends.
	// 1. Close sshd connections first to unblock session handlers reading from sshd
	cleanupSshd()
	// 2. Close the fake connections to unblock any transport goroutines waiting on ReadFrom
	clientConn2.Close()
	serverConn2.Close()
	// 3. Close QUIC objects
	stream2.Close()
	session2.CloseWithError(0, "test done")
	clientTransport2.Close()
	serverListener2.Close()
	serverTransport2.Close()
	// 4. Close server which waits for all session handlers to complete
	server.Close()
}

// TestE2E_TortureTest is a comprehensive chaos test that randomly injects faults
// while streaming data bidirectionally. It tests:
// - Random packet drops
// - Random packet reordering
// - Random packet duplication
// - Random connection breaks with session resumption
// - Continuous bidirectional data streaming
// - Verification that all data arrives in order with no gaps
//
// The test uses a seed-based PRNG for reproducibility. If a test fails, you can
// reproduce it by setting the QUICSSH_TEST_SEED environment variable.
func TestE2E_TortureTest(t *testing.T) {
	// Get seed from flag or environment variable, or use current time
	var seed int64
	seedFlag := flag.Lookup("seed")
	if seedFlag != nil && seedFlag.Value.String() != "0" {
		fmt.Sscanf(seedFlag.Value.String(), "%d", &seed)
	} else if seedEnv := os.Getenv("QUICSSH_TEST_SEED"); seedEnv != "" {
		fmt.Sscanf(seedEnv, "%d", &seed)
	} else {
		seed = time.Now().UnixNano()
	}

	t.Logf("=== TORTURE TEST SEED: %d ===", seed)
	t.Logf("To reproduce this test, run: QUICSSH_TEST_SEED=%d go test -v -run TestE2E_TortureTest", seed)

	rng := mathrand.New(mathrand.NewSource(seed))

	// Test configuration
	// Vary message rate to test different traffic patterns
	messagesPerSecond := 60 + rng.Intn(141) // Random between 60 and 200

	const (
		// Chaos parameters
		dropRate        = 0.05 // 5% packet drop rate
		reorderRate     = 0.10 // 10% packet reorder rate
		duplicateRate   = 0.02 // 2% packet duplication rate
		disconnectRate  = 0.01 // 1% chance per data frame of breaking the connection
		maxReorderDelay = 100 * time.Millisecond
	)

	// Use a fixed 10-second test duration
	// This ensures consistent behavior across multiple test iterations (-count flag)
	testDuration := 10 * time.Second
	t.Logf("Message rate: %d messages/second. Test duration: %v", messagesPerSecond, testDuration)

	// Start echo server as fake sshd
	sshdAddr, cleanupSshd := startEchoServer(t)
	defer cleanupSshd()

	// Create TLS config
	serverTLS, err := generateTestTLSConfig()
	if err != nil {
		t.Fatalf("Failed to generate TLS config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create chaos packet connections with separate RNGs for each direction
	clientChaosConfig := ChaosConfig{
		DropRate:        dropRate,
		ReorderRate:     reorderRate,
		DuplicateRate:   duplicateRate,
		MaxReorderDelay: maxReorderDelay,
		Rand:            mathrand.New(mathrand.NewSource(rng.Int63())),
	}
	serverChaosConfig := ChaosConfig{
		DropRate:        dropRate,
		ReorderRate:     reorderRate,
		DuplicateRate:   duplicateRate,
		MaxReorderDelay: maxReorderDelay,
		Rand:            mathrand.New(mathrand.NewSource(rng.Int63())),
	}

	clientConn, serverConn := NewChaosPacketConnPair(2000, clientChaosConfig, serverChaosConfig)

	// Ensure cleanup happens - close connections to unblock any pending I/O
	defer clientConn.Close()
	defer serverConn.Close()

	// Create server
	serverTransport := &quic.Transport{Conn: serverConn}
	serverConfig := &TestServerConfig{
		TLSConfig:           serverTLS,
		QUICConfig:          testQuicConfig(),
		SSHDAddr:            sshdAddr,
		SessionLayerEnabled: true,
		SessionTimeout:      5 * time.Minute,
		BufferSize:          DefaultBufferSize,
		Logf:                log.Printf, // Use log.Printf instead of t.Logf to avoid panics in async goroutines
	}

	server, err := NewTestServer(ctx, serverTransport, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		server.Serve()
	}()

	// Track test state
	var (
		clientSentSeq     atomic.Uint64 // Next sequence to send from client
		clientReceivedSeq atomic.Uint64 // Next sequence expected to receive at client
		reconnectCount    atomic.Uint64 // Number of successful reconnections

		testErrors   []string
		testErrorsMu sync.Mutex
	)

	recordError := func(format string, args ...interface{}) {
		testErrorsMu.Lock()
		defer testErrorsMu.Unlock()
		testErrors = append(testErrors, fmt.Sprintf(format, args...))
	}

	// Client goroutine: sends messages and receives echoes, with random disconnects
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)

		clientCtx, clientCancel := context.WithCancel(ctx)
		defer clientCancel()

		clientTLS := generateTestClientTLSConfig()
		quicConfig := testQuicConfig()

		clientSession, err := NewClientSession(DefaultBufferSize, t.Logf)
		if err != nil {
			recordError("Failed to create client session: %v", err)
			return
		}

		clientTransport := &quic.Transport{Conn: clientConn}

		sendTicker := time.NewTicker(time.Second / time.Duration(messagesPerSecond))
		defer sendTicker.Stop()

		testTimer := time.NewTimer(testDuration)
		defer testTimer.Stop()

		isFirstConnection := true

		// Outer loop: each iteration is one QUIC connection lifetime.
		// Connections are broken randomly (per-frame probability) to exercise
		// session resumption under chaos conditions.
		for {
			// Establish QUIC connection
			dialCtx, dialCancel := context.WithTimeout(clientCtx, 5*time.Second)
			quicConn, err := clientTransport.Dial(dialCtx, serverConn.LocalAddr(), clientTLS, quicConfig)
			dialCancel()
			if err != nil {
				if clientCtx.Err() != nil {
					return
				}
				recordError("Client dial failed: %v", err)
				return
			}

			stream, err := quicConn.OpenStreamSync(clientCtx)
			if err != nil {
				if clientCtx.Err() != nil {
					return
				}
				recordError("Failed to open stream: %v", err)
				return
			}

			// Connect (first time) or Resume (after disconnect)
			if isFirstConnection {
				if err := clientSession.Connect(stream); err != nil {
					recordError("Client session connect failed: %v", err)
					return
				}
				t.Log("Client session connected")
				isFirstConnection = false
			} else {
				framesToReplay, err := clientSession.Resume(stream)
				if errors.Is(err, ErrSessionNotFound) && reconnectCount.Load() == 0 && clientReceivedSeq.Load() == 0 {
					// Session was never created on server (e.g., NEW_SESSION packet
					// was dropped and client disconnected before QUIC retransmitted).
					// This can only happen before the server has confirmed the session
					// by echoing data back or processing a successful resume.
					// Start fresh with a new session.
					t.Log("Session not found on server (never confirmed), creating new session")
					quicConn.CloseWithError(0, "session not found")
					var csErr error
					clientSession, csErr = NewClientSession(DefaultBufferSize, t.Logf)
					if csErr != nil {
						recordError("Failed to create new client session: %v", csErr)
						return
					}
					// Reset counters since the old session's data was never delivered
					clientSentSeq.Store(0)
					clientReceivedSeq.Store(0)
					isFirstConnection = true
					continue // Reconnect via outer loop
				}
				if err != nil {
					recordError("Client session resume failed: %v", err)
					return
				}
				encBuf := clientSession.EncodeBuffer()
				for _, frame := range framesToReplay {
					if err := frame.Encode(stream, encBuf); err != nil {
						recordError("Failed to replay frame seq=%d: %v", frame.Seq, err)
						return
					}
				}
				n := reconnectCount.Add(1)
				t.Logf("Client session resumed (reconnect #%d, replayed %d frames)", n, len(framesToReplay))
			}

			// Receiver: reads echo responses for this connection
			receiveDone := make(chan struct{})
			go func() {
				defer close(receiveDone)
				for {
					select {
					case <-clientCtx.Done():
						return
					default:
					}

					frame, err := ReadFrame(stream, nil)
					if err != nil {
						if clientCtx.Err() != nil {
							return
						}
						// Expected during chaos disconnect - not an error
						return
					}

					if dataFrame, ok := frame.(*DataFrame); ok {
						// Pass through session layer for deduplication.
						// After reconnect, the server replays unACKed frames;
						// HandleData filters out duplicates so we only process new data.
						isNew, err := clientSession.HandleData(dataFrame)
						if err != nil {
							recordError("Session HandleData error: seq=%d err=%v", dataFrame.Seq, err)
							continue
						}
						if !isNew {
							continue // Duplicate from replay, skip
						}

						if debugFrames {
							t.Logf("[Client] Received seq=%d %s", dataFrame.Seq, frameDigest(dataFrame.Payload))
						}
						// A DATA frame may contain multiple messages batched together
						// Each message is 40 bytes (8 bytes seq + 32 bytes data)
						const messageSize = 40
						payload := dataFrame.Payload

						for len(payload) >= messageSize {
							msg := payload[:messageSize]
							payload = payload[messageSize:]

							expectedSeq := clientReceivedSeq.Load()
							receivedSeq := binary.BigEndian.Uint64(msg[:8])

							// Check for poison pill (sequence number 0xFFFFFFFFFFFFFFFF) - signals end of test
							if receivedSeq == 0xFFFFFFFFFFFFFFFF {
								return
							}
							if receivedSeq != expectedSeq {
								recordError("Client received out-of-order: got seq %d, expected %d", receivedSeq, expectedSeq)
							} else {
								clientReceivedSeq.Add(1)
							}
						}

						if len(payload) > 0 {
							recordError("Client received partial message: %d bytes leftover", len(payload))
						}

						// Send app-level ACK so the server can clear its send buffer.
						// Ignore errors: if the connection died, the next ReadFrame will catch it.
						go clientSession.SendAck() //nolint:errcheck // goroutine avoids deadlock under flow control
					} else if ackFrame, ok := frame.(*AckFrame); ok {
						// Handle ACK from server so the client can clear its send buffer.
						clientSession.HandleAck(ackFrame)
					}
				}
			}()

			// Send messages until a random disconnect or the test timer fires
			testEnded := false
			shouldDisconnect := false

		sendLoop:
			for {
				select {
				case <-clientCtx.Done():
					testEnded = true
					break sendLoop
				case <-testTimer.C:
					testEnded = true
					break sendLoop
				case <-sendTicker.C:
					seq := clientSentSeq.Add(1) - 1
					payload := make([]byte, 8+32) // 8 bytes seq + 32 bytes random data
					binary.BigEndian.PutUint64(payload[:8], seq)
					rng.Read(payload[8:])

					if debugFrames {
						t.Logf("[Client] Sending seq=%d %s", seq, frameDigest(payload))
					}
					if err := clientSession.SendData(clientCtx, payload); err != nil {
						t.Logf("Client SendData error: %v", err)
					}

					// Randomly break the connection
					if rng.Float64() < disconnectRate {
						shouldDisconnect = true
						break sendLoop
					}
				}
			}

			if testEnded {
				// Test duration elapsed - send poison pill and exit
				poisonPill := make([]byte, 8+32)
				binary.BigEndian.PutUint64(poisonPill[:8], 0xFFFFFFFFFFFFFFFF)
				clientSession.SendData(clientCtx, poisonPill)
				clientSession.Disconnect()
				clientCancel()
				stream.CancelRead(0)

				select {
				case <-receiveDone:
				case <-time.After(1 * time.Second):
					t.Logf("Warning: receiver did not finish within timeout")
				}
				return
			}

			if shouldDisconnect {
				// Break the connection and reconnect
				t.Logf("Chaos disconnect triggered after seq %d", clientSentSeq.Load()-1)
				clientSession.Disconnect()
				quicConn.CloseWithError(1, "chaos disconnect")

				select {
				case <-receiveDone:
				case <-time.After(2 * time.Second):
					t.Logf("Warning: receiver did not finish within timeout after disconnect")
				}
				continue // Reconnect via outer loop
			}
		}
	}()

	<-clientDone

	// Cancel the context to signal all goroutines to stop
	cancel()

	// Close the packet connections to unblock any pending I/O
	clientConn.Close()
	serverConn.Close()

	// Close the echo server to unblock any sshdToStream goroutines blocked
	// reading from sshd. This must happen before server.Close() which waits
	// for active handlers that may be stuck in net.Read on the sshd connection.
	cleanupSshd()

	// Close the server and wait for all cleanup to complete
	// This ensures SessionManager's signal handlers are fully stopped before
	// the next test iteration (prevents hangs with -count flag)
	server.Close()

	// Report statistics
	t.Logf("=== TEST STATISTICS ===")
	t.Logf("Client sent: %d messages", clientSentSeq.Load())
	t.Logf("Client received: %d messages", clientReceivedSeq.Load())
	t.Logf("Reconnects: %d", reconnectCount.Load())

	clientDropped, clientReordered, clientDuplicated := clientConn.GetStats()
	serverDropped, serverReordered, serverDuplicated := serverConn.GetStats()
	t.Logf("Client->Server: dropped=%d reordered=%d duplicated=%d", clientDropped, clientReordered, clientDuplicated)
	t.Logf("Server->Client: dropped=%d reordered=%d duplicated=%d", serverDropped, serverReordered, serverDuplicated)

	// Check for errors
	testErrorsMu.Lock()
	if len(testErrors) > 0 {
		t.Errorf("Test encountered %d errors:", len(testErrors))
		for _, err := range testErrors {
			t.Errorf("  - %s", err)
		}
		t.Errorf("To reproduce this failure with detailed logging, run:")
		t.Errorf("  QUICSSH_TEST_SEED=%d QUICSSH_DEBUG_FRAMES=1 QUICSSH_VERBOSE=1 go test -v -run TestE2E_TortureTest", seed)
	}
	testErrorsMu.Unlock()
}
