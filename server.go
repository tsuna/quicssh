package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

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

	// Determine how to load the TLS certificate
	certFile := c.String("cert")
	keyFile := c.String("key")
	insecure := c.Bool("insecure")

	config := &tls.Config{
		NextProtos: []string{"quicssh"},
	}

	if certFile != "" && keyFile != "" {
		// Load certificate from files with reload support
		log.Printf("Loading TLS certificate from %q and key from %q", certFile, keyFile)
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}

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
	} else {
		return fmt.Errorf("must specify either --cert and --key flags, or use --insecure flag")
	}

	raddr, err := net.ResolveTCPAddr("tcp", c.String("sshdaddr"))
	if err != nil {
		return err
	}

	// configure listener with moderate flow control settings
	quicConfig := &quic.Config{
		MaxIdleTimeout: c.Duration("idletimeout"),
		// Moderate flow control windows: balance between interactive and bulk transfers
		InitialStreamReceiveWindow:     2 * 1024 * 1024,  // 2 MB (default: 512 KB)
		MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16 MB (default: 6 MB)
		InitialConnectionReceiveWindow: 2 * 1024 * 1024,  // 2 MB (default: 512 KB)
		MaxConnectionReceiveWindow:     32 * 1024 * 1024, // 32 MB (default: 15 MB)
	}
	listener, err := quic.ListenAddr(c.String("bind"), config, quicConfig)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("Listening at %q... (sshd addr: %q)", c.String("bind"), c.String("sshdaddr"))

	ctx := context.Background()
	for {
		log.Printf("Accepting connection...")
		session, err := listener.Accept(ctx)
		if err != nil {
			log.Printf("listener error: %v", err)
			continue
		}

		go serverSessionHandler(ctx, session, raddr)
	}
}

func serverSessionHandler(ctx context.Context, session *quic.Conn, raddr *net.TCPAddr) {
	log.Printf("Handling session...")
	defer func() {
		if err := session.CloseWithError(0, "close"); err != nil {
			log.Printf("Session close error: %v", err)
		}
	}()
	for {
		stream, err := session.AcceptStream(ctx)
		if err != nil {
			log.Printf("Session error: %v", err)
			break
		}
		go serverStreamHandler(ctx, stream, raddr)
	}
}

func serverStreamHandler(ctx context.Context, conn io.ReadWriteCloser, raddr *net.TCPAddr) {
	log.Printf("Handling stream...")
	defer conn.Close()

	rConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		log.Printf("Dial error: %v", err)
		return
	}
	defer rConn.Close()
	// Disable Nagle's algorithm for lower latency on interactive SSH traffic
	rConn.SetNoDelay(true)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c1 := readAndWrite(ctx, conn, rConn)
	c2 := readAndWrite(ctx, rConn, conn)
	select {
	case err = <-c1:
	case err = <-c2:
	}
	if err != nil {
		log.Printf("readAndWrite error: %v", err)
		return
	}
	log.Printf("Piping finished")
}
