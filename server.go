package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"

	quic "github.com/quic-go/quic-go"
	cli "github.com/urfave/cli/v2"
)

func server(c *cli.Context) error {
	// generate TLS certificate
	key, err := rsa.GenerateKey(rand.Reader, 1024)
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
	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quicssh"},
	}

	raddr, err := net.ResolveTCPAddr("tcp", c.String("sshdaddr"))
	if err != nil {
		return err
	}

	// configure listener
	listener, err := quic.ListenAddr(c.String("bind"), config, nil)
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
	log.Printf("Hanling session...")
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
