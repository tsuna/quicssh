package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	cli "github.com/urfave/cli/v2"
)

// certManager manages TLS certificate reloading
type certManager struct {
	mu       sync.RWMutex
	cert     *tls.Certificate
	certFile string
	keyFile  string
}

func (cm *certManager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.cert, nil
}

func (cm *certManager) logCertInfo(cert *tls.Certificate) {
	if len(cert.Certificate) == 0 {
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Printf("Warning: failed to parse certificate for info: %v", err)
		return
	}

	// Log certificate details
	log.Printf("  Subject: %s", x509Cert.Subject)
	log.Printf("  Serial: %s", x509Cert.SerialNumber)
	log.Printf("  Issuer: %s", x509Cert.Issuer)
	log.Printf("  Valid from: %s", x509Cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
	log.Printf("  Valid until: %s", x509Cert.NotAfter.Format("2006-01-02 15:04:05 MST"))

	// Log DNS names and IP addresses
	if len(x509Cert.DNSNames) > 0 {
		log.Printf("  DNS names: %v", x509Cert.DNSNames)
	}
	if len(x509Cert.IPAddresses) > 0 {
		log.Printf("  IP addresses: %v", x509Cert.IPAddresses)
	}
}

func (cm *certManager) reload() error {
	log.Printf("Reloading certificate from %q and key from %q", cm.certFile, cm.keyFile)
	newCert, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
	if err != nil {
		return fmt.Errorf("failed to reload certificate: %w", err)
	}

	log.Printf("Certificate reloaded successfully:")
	cm.logCertInfo(&newCert)

	cm.mu.Lock()
	cm.cert = &newCert
	cm.mu.Unlock()

	return nil
}

func (cm *certManager) watchForReload() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		for range sigChan {
			if err := cm.reload(); err != nil {
				log.Printf("Error reloading certificate: %v", err)
			}
		}
	}()
	log.Printf("Certificate reload enabled: send SIGHUP to reload")
}

func server(c *cli.Context) error {
	var err error
	var cm *certManager

	// Set up verbose logging
	logf, logFile := createLogFunc(c)
	if logFile != nil {
		defer logFile.Close()
	}

	// Determine how to load the TLS certificate
	certFile := c.String("cert")
	keyFile := c.String("key")
	insecure := c.Bool("insecure")

	config := &tls.Config{
		NextProtos: []string{"quicssh"},
	}

	// statelessResetKey is derived from the TLS private key so that after a server
	// restart, clients with old connections receive valid STATELESS_RESET packets
	// and can quickly detect the server restart and attempt to reconnect.
	var statelessResetKey *quic.StatelessResetKey

	if certFile != "" && keyFile != "" {
		// Load certificate from files with reload support
		log.Printf("Loading TLS certificate from %q and key from %q", certFile, keyFile)
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}

		// Derive StatelessResetKey from the key file contents
		// This ensures the same key is used across server restarts
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read key file for stateless reset key: %w", err)
		}
		hash := sha256.Sum256(keyBytes)
		statelessResetKey = (*quic.StatelessResetKey)(&hash)

		cm = &certManager{
			cert:     &tlsCert,
			certFile: certFile,
			keyFile:  keyFile,
		}

		// Log certificate information
		log.Printf("Certificate loaded:")
		cm.logCertInfo(&tlsCert)

		// Use GetCertificate callback for dynamic certificate loading
		config.GetCertificate = cm.getCertificate

		// Set up SIGHUP handler for certificate reloading
		cm.watchForReload()
	} else if insecure {
		// Generate self-signed certificate
		log.Printf("WARNING: Generating self-signed certificate (insecure mode)")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		template := x509.Certificate{SerialNumber: big.NewInt(1)}
		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			return err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return err
		}
		config.Certificates = []tls.Certificate{tlsCert}

		// For insecure mode, derive key from the generated private key
		hash := sha256.Sum256(keyPEM)
		statelessResetKey = (*quic.StatelessResetKey)(&hash)
	} else {
		return fmt.Errorf("must specify either --cert and --key flags, or use --insecure flag")
	}

	raddr, err := net.ResolveTCPAddr("tcp", c.String("sshdaddr"))
	if err != nil {
		return err
	}

	// Create UDP socket manually so we can configure it for resilience
	udpAddr, err := net.ResolveUDPAddr("udp", c.String("bind"))
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	// Configure the UDP socket to be resilient to network hiccups.
	// On Linux this disables IP_RECVERR to prevent ICMP "destination
	// unreachable" messages from causing issues during client VPN
	// reconnects or temporary network outages.
	if err := configureUDPSocket(udpConn); err != nil {
		log.Printf("Warning: failed to configure UDP socket for resilience: %v", err)
		// Continue anyway, this is just an optimization
	}

	// Session layer support
	sessionLayerEnabled := c.Bool("session-layer")
	bufferSize := c.Int("buffer-size")

	// Determine QUIC idle timeout
	var quicIdleTimeout time.Duration
	if sessionLayerEnabled {
		// When session layer is enabled, use session timeout as QUIC idle timeout
		// since the session layer handles reconnection
		quicIdleTimeout = c.Duration("session-timeout")
		if c.IsSet("idle-timeout") {
			log.Printf("Warning: --idle-timeout is ignored when --session-layer is enabled (using session-timeout instead)")
		}
	} else {
		quicIdleTimeout = c.Duration("idle-timeout")
	}

	quicConfig := newQUICConfig(quicIdleTimeout, bufferSize)
	logf("QUIC config: IdleTimeout=%v, KeepAlivePeriod=%v, MaxStreamReceiveWindow=%d", quicConfig.MaxIdleTimeout, quicConfig.KeepAlivePeriod, quicConfig.MaxStreamReceiveWindow)

	// Create a Transport with StatelessResetKey so that after a server restart,
	// clients with old connections receive valid STATELESS_RESET packets and can
	// quickly detect the restart and attempt to reconnect.
	transport := &quic.Transport{
		Conn:              udpConn,
		StatelessResetKey: statelessResetKey,
	}
	defer transport.Close()

	listener, err := transport.Listen(config, quicConfig)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("Listening at %q... (sshd addr: %q)", c.String("bind"), c.String("sshdaddr"))

	ctx := context.Background()

	var sessionManager *SessionManager
	var sessionHandler *SessionStreamHandler

	if sessionLayerEnabled {
		sessionTimeout := c.Duration("session-timeout")
		maxSessions := c.Int("max-sessions")
		sessionManager = NewSessionManager(ctx, c.String("sshdaddr"), sessionTimeout, maxSessions, bufferSize, logf)
		sessionHandler = NewSessionStreamHandler(sessionManager, quicIdleTimeout, logf)
		log.Printf("Session layer enabled (session-timeout: %v, max-sessions: %d, buffer-size: %d)", sessionTimeout, maxSessions, bufferSize)
	}

	for {
		logf("Waiting to accept connection...")
		session, err := listener.Accept(ctx)
		if err != nil {
			log.Printf("listener error: %v", err)
			continue
		}

		log.Printf("Accepted connection from %v (local: %v)", session.RemoteAddr(), session.LocalAddr())
		go serverSessionHandler(ctx, session, raddr, quicIdleTimeout, logf, sessionLayerEnabled, sessionHandler)
	}
}

func serverSessionHandler(ctx context.Context, session *quic.Conn, raddr *net.TCPAddr, idleTimeout time.Duration, logf logFunc, sessionLayerEnabled bool, sessionHandler *SessionStreamHandler) {
	remoteAddr := session.RemoteAddr()
	logf("[session %v] Handling session...", remoteAddr)

	// Monitor connection context for closure
	go func() {
		<-session.Context().Done()
		logf("[session %v] QUIC session context done: %v", remoteAddr, context.Cause(session.Context()))
	}()

	defer func() {
		logf("[session %v] Closing session...", remoteAddr)
		if err := session.CloseWithError(0, "close"); err != nil {
			log.Printf("[session %v] Session close error: %v", remoteAddr, err)
		}
	}()
	for {
		logf("[session %v] Waiting to accept stream...", remoteAddr)
		stream, err := session.AcceptStream(ctx)
		if err != nil {
			log.Printf("[session %v] Session error: %v (type: %T)", remoteAddr, err, err)
			break
		}
		logf("[session %v] Accepted stream ID=%v", remoteAddr, stream.StreamID())

		// Capture stream in a local variable for the goroutine
		s := stream
		if sessionLayerEnabled && sessionHandler != nil {
			go func() {
				if err := sessionHandler.HandleStream(ctx, s, session, remoteAddr.String()); err != nil {
					log.Printf("[stream %v from %v] Session handler error: %v", s.StreamID(), remoteAddr, err)
				}
			}()
		} else {
			go serverStreamHandler(ctx, s, raddr, idleTimeout, logf, remoteAddr)
		}
	}
}

func serverStreamHandler(ctx context.Context, stream *quic.Stream, raddr *net.TCPAddr, idleTimeout time.Duration, logf logFunc, clientAddr net.Addr) {
	streamID := stream.StreamID()
	logf("[stream %v from %v] Handling stream...", streamID, clientAddr)
	defer func() {
		logf("[stream %v from %v] Closing stream...", streamID, clientAddr)
		stream.Close()
	}()

	logf("[stream %v from %v] Dialing sshd at %v...", streamID, clientAddr, raddr)
	rConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		log.Printf("[stream %v from %v] Dial error: %v", streamID, clientAddr, err)
		return
	}
	logf("[stream %v from %v] Connected to sshd: local=%v remote=%v", streamID, clientAddr, rConn.LocalAddr(), rConn.RemoteAddr())
	defer rConn.Close()
	// Disable Nagle's algorithm for lower latency on interactive SSH traffic
	rConn.SetNoDelay(true)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logf("[stream %v from %v] Starting bidirectional piping (idleTimeout=%v)...", streamID, clientAddr, idleTimeout)
	c1 := readAndWrite(ctx, stream, rConn, idleTimeout, logf)
	c2 := readAndWrite(ctx, rConn, stream, idleTimeout, logf)
	select {
	case err = <-c1:
		logf("[stream %v from %v] QUIC->sshd goroutine exited: %v", streamID, clientAddr, err)
	case err = <-c2:
		logf("[stream %v from %v] sshd->QUIC goroutine exited: %v", streamID, clientAddr, err)
	}
	if err != nil {
		log.Printf("[stream %v from %v] readAndWrite error: %v", streamID, clientAddr, err)
		return
	}
	log.Printf("[stream %v from %v] Piping finished", streamID, clientAddr)
}
