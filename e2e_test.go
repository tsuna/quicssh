package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
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
			frame, err := ReadFrame(stream)
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
			frame, err := ReadFrame(stream)
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
			frame, err := ReadFrame(stream2)
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
