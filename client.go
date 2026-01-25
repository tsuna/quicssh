package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	cli "github.com/urfave/cli/v2"
)

func client(c *cli.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handler for graceful shutdown.
	// With UDP/QUIC, the kernel won't automatically notify the server when we die
	// (unlike TCP which sends RST), so we need to explicitly close the connection.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		select {
		case sig := <-sigCh:
			log.Printf("Received signal %v, shutting down gracefully...", sig)
			cancel() // This triggers deferred cleanup of QUIC session
		case <-ctx.Done():
		}
	}()
	defer signal.Stop(sigCh)

	verbose := c.Bool("verbose")
	logf := func(format string, v ...interface{}) {
		if verbose {
			log.Printf(format, v...)
		}
	}

	// Check if we should bypass QUIC for bulk transfers (scp, rsync, sftp)
	if !c.Bool("no-passthrough") {
		if isBulk, cmd := isBulkTransferParent(); isBulk {
			sshPort := c.Int("ssh-port")
			// Extract hostname from addr (strip port)
			addr := c.String("addr")
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr // assume no port
			}
			logf("Detected %s, using direct SSH connection to %s:%d", cmd, host, sshPort)
			return tcpPassthrough(ctx, host, sshPort)
		}
	}

	// Configure TLS based on flags
	serverCertFile := c.String("servercert")
	insecure := c.Bool("insecure")
	skipVerifyHostname := c.Bool("skip-verify-hostname")

	config := &tls.Config{
		NextProtos: []string{"quicssh"},
		// Enable TLS session caching for 0-RTT resumption on reconnects
		ClientSessionCache: tls.NewLRUClientSessionCache(10),
	}

	if serverCertFile != "" {
		// Load and verify server certificate
		logf("Loading server certificate from %q for verification", serverCertFile)
		certPEM, err := os.ReadFile(serverCertFile)
		if err != nil {
			return fmt.Errorf("failed to read server certificate: %w", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certPEM) {
			return fmt.Errorf("failed to parse server certificate")
		}
		config.RootCAs = certPool
		config.InsecureSkipVerify = false

		// Skip hostname verification if requested (still verifies the cert itself)
		if skipVerifyHostname {
			log.Printf("WARNING: Skipping hostname verification (certificate is still verified)")
			config.InsecureSkipVerify = true
			config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				// Parse the certificate
				if len(rawCerts) == 0 {
					return fmt.Errorf("no certificates provided")
				}
				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %w", err)
				}

				// Verify against our trusted cert pool
				opts := x509.VerifyOptions{
					Roots:         certPool,
					Intermediates: x509.NewCertPool(),
				}
				if _, err := cert.Verify(opts); err != nil {
					return fmt.Errorf("certificate verification failed: %w", err)
				}
				return nil
			}
		}
	} else if insecure {
		// Skip certificate verification
		log.Printf("WARNING: Skipping TLS certificate verification (insecure mode)")
		config.InsecureSkipVerify = true
	} else {
		return fmt.Errorf("must specify either --servercert flag, or use --insecure flag")
	}

	// Parse the remote address to extract hostname and port for later re-resolution
	remoteAddrStr := c.String("addr")
	remoteHost, remotePortStr, err := net.SplitHostPort(remoteAddrStr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", remoteAddrStr, err)
	}
	remotePort, err := net.LookupPort("udp", remotePortStr)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", remotePortStr, err)
	}

	// Resolve DNS once upfront - this cached address will be used for the
	// initial connection, but may be re-resolved during path migration
	udpAddr, err := net.ResolveUDPAddr("udp", remoteAddrStr)
	if err != nil {
		return err
	}
	srcAddr, err := net.ResolveUDPAddr("udp", c.String("localaddr"))
	if err != nil {
		return err
	}

	logf("Dialing %q->%q...", srcAddr.String(), udpAddr.String())
	conn, err := net.ListenUDP("udp", srcAddr)
	if err != nil {
		return err
	}
	logf("Local UDP socket bound to %v", conn.LocalAddr())

	// Configure the UDP socket to be resilient to network hiccups.
	// On Linux this disables IP_RECVERR to prevent ICMP "destination
	// unreachable" messages from breaking the connection during VPN
	// reconnects or temporary network outages.
	if err := configureUDPSocket(conn); err != nil {
		logf("Warning: failed to configure UDP socket for resilience: %v", err)
		// Continue anyway, this is just an optimization
	}

	bufferSize := c.Int("buffer-size")
	sessionLayerEnabled := c.Bool("session-layer")

	// Determine QUIC idle timeout
	var quicIdleTimeout time.Duration
	if sessionLayerEnabled {
		// When session layer is enabled, use 24h as QUIC idle timeout
		// since the session layer handles reconnection and we don't know
		// the server's session timeout
		quicIdleTimeout = 24 * time.Hour
		if c.IsSet("idle-timeout") {
			log.Printf("Warning: --idle-timeout is ignored when --session-layer is enabled")
		}
	} else {
		quicIdleTimeout = c.Duration("idle-timeout")
	}

	quicConfig := newQUICConfig(quicIdleTimeout, bufferSize)
	logf("QUIC config: IdleTimeout=%v, KeepAlivePeriod=%v, MaxStreamReceiveWindow=%d", quicConfig.MaxIdleTimeout, quicConfig.KeepAlivePeriod, quicConfig.MaxStreamReceiveWindow)

	// Create a Transport so we can use AddPath for connection migration
	transport := &quic.Transport{Conn: conn}
	defer transport.Close()

	session, err := transport.Dial(ctx, udpAddr, config, quicConfig)
	if err != nil {
		logf("QUIC dial error: %v (type: %T)", err, err)
		return err
	}
	logf("QUIC connection established: local=%v remote=%v", session.LocalAddr(), session.RemoteAddr())
	defer func() {
		logf("Closing QUIC session...")
		if err := session.CloseWithError(0, "close"); err != nil {
			log.Printf("session close error: %v", err)
		}
	}()

	// Monitor connection context for closure
	go func() {
		<-session.Context().Done()
		logf("QUIC session context done: %v", context.Cause(session.Context()))
	}()

	logf("Opening stream sync...")
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		logf("OpenStreamSync error: %v (type: %T)", err, err)
		return err
	}
	logf("Stream opened: ID=%v", stream.StreamID())
	defer func() {
		logf("Closing stream...")
		stream.Close()
	}()
	if sessionLayerEnabled {
		logf("Session layer enabled")
		cfg := &sessionLayerConfig{
			remoteHost:  remoteHost,
			remotePort:  remotePort,
			localAddr:   c.String("localaddr"),
			tlsConfig:   config,
			quicConfig:  quicConfig,
			initialConn: session,
			bufferSize:  bufferSize,
			logf:        logf,
		}
		return runClientSessionLayer(ctx, stream, cfg)
	}

	// Start path migration monitor to handle VPN IP changes
	pathCheckInterval := c.Duration("path-check-interval")
	var onNetworkTrouble networkTroubleCallback
	if pathCheckInterval > 0 {
		pm := newPathMigrator(session, remoteHost, remotePort, udpAddr, config, quicConfig, pathCheckInterval, logf)
		go pm.monitor(ctx)
		onNetworkTrouble = pm.SignalNetworkTrouble
	} else {
		logf("Path migration disabled (path-check-interval=0)")
	}

	logf("Piping stream with QUIC (idleTimeout=%v)...", quicIdleTimeout)
	var c1, c2 <-chan error
	if onNetworkTrouble != nil {
		c1 = readAndWrite(ctx, stream, os.Stdout, quicIdleTimeout, logf, onNetworkTrouble)
		c2 = readAndWrite(ctx, os.Stdin, stream, quicIdleTimeout, logf, onNetworkTrouble)
	} else {
		c1 = readAndWrite(ctx, stream, os.Stdout, quicIdleTimeout, logf)
		c2 = readAndWrite(ctx, os.Stdin, stream, quicIdleTimeout, logf)
	}
	select {
	case err = <-c1:
		logf("Stream->stdout goroutine exited: %v", err)
	case err = <-c2:
		logf("Stdin->stream goroutine exited: %v", err)
	}
	if err != nil {
		return err
	}
	return nil
}

// sessionLayerConfig holds configuration for the session layer reconnection logic.
type sessionLayerConfig struct {
	remoteHost  string
	remotePort  int
	localAddr   string
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	initialConn *quic.Conn // Initial QUIC connection (for ACK hook)
	bufferSize  int        // Maximum size of send buffer
	logf        logFunc
}

// runClientSessionLayer runs the client with session layer protocol.
// This wraps stdin/stdout with DATA frames and handles ACKs.
// It includes automatic reconnection logic to handle VPN switches.
func runClientSessionLayer(ctx context.Context, stream *quic.Stream, cfg *sessionLayerConfig) error {
	logf := cfg.logf

	// Create client session
	clientSession, err := NewClientSession(cfg.bufferSize, logf)
	if err != nil {
		return fmt.Errorf("failed to create client session: %w", err)
	}

	// Install ACK hook on the initial QUIC connection
	if cfg.initialConn != nil {
		clientSession.SetQUICConn(cfg.initialConn)
	}

	// Connect with NEW_SESSION handshake
	if err := clientSession.Connect(stream); err != nil {
		return fmt.Errorf("session connect failed: %w", err)
	}

	// Run the session loop with reconnection support
	return runSessionLoopWithReconnect(ctx, clientSession, cfg)
}

// runSessionLoopWithReconnect runs the bidirectional data flow and handles reconnection.
func runSessionLoopWithReconnect(ctx context.Context, clientSession *ClientSession, cfg *sessionLayerConfig) error {
	logf := cfg.logf

	// Set up SIGUSR1 handler to dump session stats
	sigUSR1 := make(chan os.Signal, 1)
	signal.Notify(sigUSR1, syscall.SIGUSR1)
	defer signal.Stop(sigUSR1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigUSR1:
				clientSession.DumpStats()
			}
		}
	}()

	for {
		// Create a child context for this connection attempt
		connCtx, connCancel := context.WithCancel(ctx)

		// Run the session loop
		err := runSessionLoop(connCtx, clientSession, logf)

		connCancel()

		// Check if we should exit
		if err == nil || err == io.EOF {
			logf("Session ended normally")
			return nil
		}

		// Check if parent context is done
		if ctx.Err() != nil {
			logf("Parent context cancelled: %v", ctx.Err())
			return ctx.Err()
		}

		// Check if this is a recoverable error (connection lost)
		if !isRecoverableError(err) {
			logf("Non-recoverable error: %v", err)
			return err
		}

		logf("Connection lost: %v - attempting to reconnect...", err)

		// Mark session as disconnected
		clientSession.Disconnect()

		// Attempt to reconnect
		if err := attemptReconnect(ctx, clientSession, cfg); err != nil {
			logf("Reconnection failed: %v", err)
			return fmt.Errorf("reconnection failed: %w", err)
		}

		logf("Reconnection successful, resuming session")
		// Loop continues with the new connection
	}
}

// runSessionLoop runs the bidirectional data flow for a single connection.
func runSessionLoop(ctx context.Context, clientSession *ClientSession, logf logFunc) error {
	errCh := make(chan error, 2)

	// Goroutine: stdin -> session -> stream
	go func() {
		errCh <- clientStdinToSession(ctx, clientSession, logf)
	}()

	// Goroutine: stream -> session -> stdout
	go func() {
		errCh <- clientSessionToStdout(ctx, clientSession, logf)
	}()

	// Wait for either goroutine to finish
	err := <-errCh

	if err != nil && err != io.EOF && err != context.Canceled {
		logf("Session loop error: %v", err)
	}

	return err
}

// isRecoverableError returns true if the error indicates a connection loss
// that can potentially be recovered by reconnecting.
func isRecoverableError(err error) bool {
	if err == nil || err == io.EOF {
		return false
	}

	errStr := err.Error()

	// QUIC-specific errors that indicate connection loss
	if contains(errStr, "no recent network activity") ||
		contains(errStr, "timeout") ||
		contains(errStr, "connection refused") ||
		contains(errStr, "network is unreachable") ||
		contains(errStr, "no route to host") ||
		contains(errStr, "Application error 0x0") ||
		contains(errStr, "stateless reset") { // Server restarted
		return true
	}

	return false
}

// contains is a simple substring check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// attemptReconnect tries to establish a new QUIC connection and resume the session.
// It uses exponential backoff and retries indefinitely until the context is cancelled.
func attemptReconnect(ctx context.Context, clientSession *ClientSession, cfg *sessionLayerConfig) error {
	logf := cfg.logf

	const (
		initialBackoff = 1 * time.Second
		maxBackoff     = 10 * time.Second
		backoffFactor  = 1.3
	)

	backoff := initialBackoff
	attempt := 0
	startTime := time.Now()
	disable0RTT := false // Set to true after 0-RTT rejection to avoid repeated failures

	for {
		attempt++

		// Check if context is cancelled
		if ctx.Err() != nil {
			return ctx.Err()
		}

		elapsed := time.Since(startTime).Round(time.Second)
		logf("Reconnection attempt %d (elapsed: %v, next backoff: %v)...", attempt, elapsed, backoff)

		// Re-resolve DNS to get potentially new server IP
		remoteAddrStr := fmt.Sprintf("%s:%d", cfg.remoteHost, cfg.remotePort)
		udpAddr, err := net.ResolveUDPAddr("udp", remoteAddrStr)
		if err != nil {
			logf("DNS resolution failed: %v", err)
			if !sleepWithContext(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, maxBackoff, backoffFactor)
			continue
		}
		logf("Resolved %s to %v", cfg.remoteHost, udpAddr)

		// Create new UDP socket
		srcAddr, err := net.ResolveUDPAddr("udp", cfg.localAddr)
		if err != nil {
			logf("Failed to resolve local address: %v", err)
			if !sleepWithContext(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, maxBackoff, backoffFactor)
			continue
		}

		conn, err := net.ListenUDP("udp", srcAddr)
		if err != nil {
			logf("Failed to create UDP socket: %v", err)
			if !sleepWithContext(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, maxBackoff, backoffFactor)
			continue
		}

		// Configure socket for resilience
		if err := configureUDPSocket(conn); err != nil {
			logf("Warning: failed to configure UDP socket: %v", err)
		}

		// Create QUIC transport
		transport := &quic.Transport{Conn: conn}

		// Dial with timeout
		// Use DialEarly for 0-RTT on reconnects, unless we've previously had 0-RTT rejected
		// (e.g., after a server restart that invalidated TLS session tickets)
		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		var session *quic.Conn
		if disable0RTT {
			session, err = transport.Dial(dialCtx, udpAddr, cfg.tlsConfig, cfg.quicConfig)
		} else {
			session, err = transport.DialEarly(dialCtx, udpAddr, cfg.tlsConfig, cfg.quicConfig)
		}
		dialCancel()

		if err != nil {
			logf("QUIC dial failed: %v", err)
			transport.Close()
			conn.Close()
			if !sleepWithContext(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, maxBackoff, backoffFactor)
			continue
		}

		logf("QUIC connection established: local=%v remote=%v", session.LocalAddr(), session.RemoteAddr())

		// Install ACK hook on the new connection
		clientSession.SetQUICConn(session)

		// Open stream
		stream, err := session.OpenStreamSync(ctx)
		if err != nil {
			logf("Failed to open stream: %v", err)
			session.CloseWithError(0, "stream open failed")
			transport.Close()
			conn.Close()
			if !sleepWithContext(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, maxBackoff, backoffFactor)
			continue
		}

		logf("Stream opened: ID=%v", stream.StreamID())

		// Resume session
		framesToReplay, err := clientSession.Resume(stream)
		if err != nil {
			logf("Session resume failed: %v", err)
			stream.Close()
			session.CloseWithError(0, "resume failed")
			transport.Close()
			conn.Close()

			// If the server doesn't recognize our session (e.g., server restarted),
			// there's no point retrying - the session is gone forever
			if errors.Is(err, ErrSessionNotFound) {
				return fmt.Errorf("session no longer exists on server (server may have restarted): %w", err)
			}

			// If 0-RTT was rejected (e.g., server restarted and lost TLS session tickets),
			// retry without 0-RTT. The session resume will then work on a 1-RTT connection.
			if errors.Is(err, quic.Err0RTTRejected) {
				logf("0-RTT rejected, retrying with 1-RTT connection...")
				disable0RTT = true
				// Don't sleep, retry immediately with 1-RTT
				continue
			}

			if !sleepWithContext(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, maxBackoff, backoffFactor)
			continue
		}

		// Replay unacknowledged frames
		if len(framesToReplay) > 0 {
			logf("Replaying %d unacknowledged frames...", len(framesToReplay))
			encBuf := clientSession.EncodeBuffer()
			for _, frame := range framesToReplay {
				if err := frame.Encode(stream, encBuf); err != nil {
					logf("Failed to replay frame seq=%d: %v", frame.Seq, err)
					stream.Close()
					session.CloseWithError(0, "replay failed")
					transport.Close()
					conn.Close()
					if !sleepWithContext(ctx, backoff) {
						return ctx.Err()
					}
					backoff = nextBackoff(backoff, maxBackoff, backoffFactor)
					continue
				}
				// Record the replayed write for ACK tracking
				clientSession.RecordWrite(frame.Seq)
			}
			logf("Replay complete")
		}

		// Success! Start monitoring the new connection
		go func() {
			<-session.Context().Done()
			logf("QUIC session context done: %v", context.Cause(session.Context()))
		}()

		logf("Reconnection successful after %d attempts (%v elapsed)", attempt, time.Since(startTime).Round(time.Second))
		return nil
	}
}

// nextBackoff calculates the next backoff duration with exponential growth up to a maximum.
func nextBackoff(current, max time.Duration, factor float64) time.Duration {
	next := time.Duration(float64(current) * factor)
	if next > max {
		return max
	}
	return next
}

// sleepWithContext sleeps for the given duration or until the context is cancelled.
// Returns true if the sleep completed, false if the context was cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// clientStdinToSession reads from stdin and sends DATA frames.
func clientStdinToSession(ctx context.Context, session *ClientSession, logf logFunc) error {
	buf := make([]byte, 32*1024)
	backpressureLogged := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Backpressure: wait if send buffer is full
		// This prevents us from reading more data from stdin than we can buffer
		for session.SendBufferIsFull(len(buf)) {
			if !backpressureLogged {
				logf("Send buffer full (%d bytes), applying backpressure on stdin",
					session.SendBufferSize())
				backpressureLogged = true
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
				// Check again
			}
		}
		if backpressureLogged {
			logf("Send buffer has space (%d bytes), resuming stdin reads",
				session.SendBufferSize())
			backpressureLogged = false
		}

		n, err := os.Stdin.Read(buf)
		if err != nil {
			if err == io.EOF {
				// stdin closed - send CLOSE frame
				logf("stdin EOF, closing session")
				session.Close("stdin closed")
				return nil
			}
			return fmt.Errorf("stdin read error: %w", err)
		}

		if n > 0 {
			if err := session.SendData(ctx, buf[:n]); err != nil {
				return fmt.Errorf("send data error: %w", err)
			}
		}
	}
}

// clientSessionToStdout reads DATA frames and writes to stdout.
// ACKs are handled at the QUIC level via the ACK hook mechanism.
func clientSessionToStdout(ctx context.Context, session *ClientSession, logf logFunc) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		frame, err := session.ReadFrame()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read frame error: %w", err)
		}

		switch f := frame.(type) {
		case *DataFrame:
			// Check for duplicate
			if !session.HandleData(f) {
				logf("Duplicate frame seq=%d, ignoring", f.Seq)
				continue
			}

			// Write to stdout
			if _, err := os.Stdout.Write(f.Payload); err != nil {
				return fmt.Errorf("stdout write error: %w", err)
			}

		case *AckFrame:
			// Handle ACK frames from old servers for backward compatibility
			session.HandleAck(f)

		case *CloseFrame:
			logf("Received CLOSE: %s", f.Reason)
			return nil

		default:
			logf("Unexpected frame type: %T", frame)
		}
	}
}

// tcpPassthrough connects directly to SSH over TCP, bypassing QUIC.
// Used when bulk transfer tools (scp, rsync, sftp) are detected.
// Uses io.Copy which automatically uses splice() on Linux when copying
// between the TCP socket and stdin/stdout pipes.
func tcpPassthrough(ctx context.Context, host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()

	// Set TCP_NODELAY for lower latency
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	errCh := make(chan error, 2)

	// conn -> stdout (Go uses splice on Linux when dst is a pipe)
	go func() {
		_, err := io.Copy(os.Stdout, conn)
		errCh <- err
	}()

	// stdin -> conn (Go uses splice on Linux when src is a pipe)
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		errCh <- err
	}()

	// Return on first completion (EOF or error)
	return <-errCh
}

// pathMigrator periodically checks for network changes and attempts QUIC path migration
// when the client's IP changes but the server IP stays the same.
// Note: Path migration only works when the SERVER IP stays the same. If the server IP
// changes (e.g., switching between VPNs that route to different server IPs), the existing
// QUIC connection cannot be migrated - a new connection would be needed.
type pathMigrator struct {
	session        *quic.Conn
	remoteHost     string // hostname for DNS re-resolution
	remotePort     int
	originalServer *net.UDPAddr // the server IP when connection was established
	tlsConfig      *tls.Config
	quicConfig     *quic.Config
	checkInterval  time.Duration
	logf           logFunc

	mu              sync.Mutex
	currentPath     *quic.Path
	lastMigrationOK bool // true if last migration succeeded (to avoid spamming logs)

	// networkTrouble is signaled when the data path detects network issues
	// (e.g., repeated timeouts). This triggers an immediate migration attempt.
	networkTrouble chan struct{}
}

func newPathMigrator(session *quic.Conn, remoteHost string, remotePort int, remoteAddr *net.UDPAddr, tlsConfig *tls.Config, quicConfig *quic.Config, checkInterval time.Duration, logf logFunc) *pathMigrator {
	pm := &pathMigrator{
		session:         session,
		remoteHost:      remoteHost,
		remotePort:      remotePort,
		originalServer:  remoteAddr,
		tlsConfig:       tlsConfig,
		quicConfig:      quicConfig,
		checkInterval:   checkInterval,
		logf:            logf,
		lastMigrationOK: true, // assume connection is healthy initially
		networkTrouble:  make(chan struct{}, 1),
	}

	logf("[pathMigrator] Initialized: host=%v server=%v checkInterval=%v", remoteHost, remoteAddr, checkInterval)
	return pm
}

// SignalNetworkTrouble signals that the data path is experiencing network issues.
// This triggers an immediate migration attempt (non-blocking).
func (pm *pathMigrator) SignalNetworkTrouble() {
	select {
	case pm.networkTrouble <- struct{}{}:
		// Signal sent
	default:
		// Channel already has a signal pending, don't block
	}
}

func (pm *pathMigrator) monitor(ctx context.Context) {
	pm.logf("[pathMigrator] Starting path migration monitor (checking every %v)", pm.checkInterval)

	ticker := time.NewTicker(pm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			pm.logf("[pathMigrator] Context done, stopping monitor: %v", ctx.Err())
			return
		case <-pm.session.Context().Done():
			pm.logf("[pathMigrator] Session closed, stopping monitor: %v", context.Cause(pm.session.Context()))
			return
		case <-pm.networkTrouble:
			pm.logf("[pathMigrator] Network trouble signaled, attempting migration...")
			pm.mu.Lock()
			pm.lastMigrationOK = false // Mark as having issues to trigger migration
			pm.mu.Unlock()
			pm.checkAndMigrate(ctx)
		case <-ticker.C:
			pm.checkAndMigrate(ctx)
		}
	}
}

func (pm *pathMigrator) checkAndMigrate(ctx context.Context) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// First, check if the server IP has changed by re-resolving DNS
	newServerAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", pm.remoteHost, pm.remotePort))
	if err != nil {
		// DNS resolution failed - network might be down, will retry later
		if pm.lastMigrationOK {
			pm.logf("[pathMigrator] DNS resolution failed: %v (will retry)", err)
			pm.lastMigrationOK = false
		}
		return
	}

	// Check if server IP changed - if so, path migration won't help
	// QUIC path migration only works when the server IP stays the same.
	// When the server IP changes (e.g., switching VPNs), the existing
	// QUIC connection cannot be migrated - a new SSH connection is needed.
	if !newServerAddr.IP.Equal(pm.originalServer.IP) {
		if pm.lastMigrationOK {
			pm.logf("[pathMigrator] Server IP changed: %v -> %v", pm.originalServer.IP, newServerAddr.IP)
			pm.logf("[pathMigrator] Path migration cannot help when server IP changes - need new SSH connection")
			pm.lastMigrationOK = false
		}
		return
	}

	// Server IP is the same - only attempt migration if we previously had issues
	// (to avoid unnecessary overhead when connection is healthy)
	if pm.lastMigrationOK {
		return // Connection is healthy, no need to migrate
	}

	// We had issues before, try to migrate to restore connectivity
	pm.logf("[pathMigrator] Attempting path migration to restore connectivity...")

	if err := pm.migrate(ctx); err != nil {
		pm.logf("[pathMigrator] Migration failed: %v (will retry)", err)
	} else {
		pm.logf("[pathMigrator] Migration successful! Connection restored.")
		pm.lastMigrationOK = true
	}
}

func (pm *pathMigrator) migrate(ctx context.Context) error {
	// Create a new UDP socket (bound to 0.0.0.0:0 to pick up the new interface)
	newConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("failed to create new UDP socket: %w", err)
	}

	// Configure the new socket for resilience
	if err := configureUDPSocket(newConn); err != nil {
		pm.logf("[pathMigrator] Warning: failed to configure new UDP socket: %v", err)
	}

	// Create a new Transport with the new socket
	newTransport := &quic.Transport{Conn: newConn}

	// Add the new path to the existing connection
	newPath, err := pm.session.AddPath(newTransport)
	if err != nil {
		newTransport.Close()
		newConn.Close()
		return fmt.Errorf("failed to add path: %w", err)
	}

	// Probe the new path to verify it works
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := newPath.Probe(probeCtx); err != nil {
		// Don't close the transport here - the path may still be usable
		return fmt.Errorf("probe failed: %w", err)
	}

	// Switch to the new path
	if err := newPath.Switch(); err != nil {
		return fmt.Errorf("switch failed: %w", err)
	}

	pm.currentPath = newPath
	pm.logf("[pathMigrator] Migrated to new path: local=%v remote=%v", newConn.LocalAddr(), pm.originalServer)

	return nil
}
