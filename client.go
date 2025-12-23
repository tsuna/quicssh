package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	quic "github.com/quic-go/quic-go"
	cli "github.com/urfave/cli/v2"
)

func client(c *cli.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	udpAddr, err := net.ResolveUDPAddr("udp", c.String("addr"))
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
	session, err := quic.Dial(ctx, conn, udpAddr, config, newQUICConfig(c.Duration("idletimeout")))
	if err != nil {
		return err
	}
	defer func() {
		if err := session.CloseWithError(0, "close"); err != nil {
			log.Printf("session close error: %v", err)
		}
	}()

	logf("Opening stream sync...")
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	logf("Piping stream with QUIC...")
	c1 := readAndWrite(ctx, stream, os.Stdout)
	c2 := readAndWrite(ctx, os.Stdin, stream)
	select {
	case err = <-c1:
	case err = <-c2:
	}
	if err != nil {
		return err
	}
	return nil
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
