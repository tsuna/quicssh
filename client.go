package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
	cli "github.com/urfave/cli/v2"
)

func client(c *cli.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Configure TLS based on flags
	serverCertFile := c.String("servercert")
	insecure := c.Bool("insecure")
	skipVerifyHostname := c.Bool("skip-verify-hostname")

	config := &tls.Config{
		NextProtos: []string{"quicssh"},
	}

	if serverCertFile != "" {
		// Load and verify server certificate
		log.Printf("Loading server certificate from %q for verification", serverCertFile)
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

	log.Printf("Dialing %q->%q...", srcAddr.String(), udpAddr.String())
	conn, err := net.ListenUDP("udp", srcAddr)
	if err != nil {
		return err
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:  c.Duration("idletimeout"),
		KeepAlivePeriod: 5 * time.Second,
		// Moderate flow control windows: balance between interactive and bulk transfers
		InitialStreamReceiveWindow:     2 * 1024 * 1024,  // 2 MB (default: 512 KB)
		MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16 MB (default: 6 MB)
		InitialConnectionReceiveWindow: 2 * 1024 * 1024,  // 2 MB (default: 512 KB)
		MaxConnectionReceiveWindow:     32 * 1024 * 1024, // 32 MB (default: 15 MB)
	}
	session, err := quic.Dial(ctx, conn, udpAddr, config, quicConfig)
	if err != nil {
		return err
	}
	defer func() {
		if err := session.CloseWithError(0, "close"); err != nil {
			log.Printf("session close error: %v", err)
		}
	}()

	log.Printf("Opening stream sync...")
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	log.Printf("Piping stream with QUIC...")
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
