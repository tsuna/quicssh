package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// testAckCallback implements quic.AckHookCallback for testing
type testAckCallback struct {
	mu    sync.Mutex
	acked []quic.PacketNumber
	lost  []quic.PacketNumber
}

func (c *testAckCallback) OnPacketsAcked(packets []quic.PacketNumber) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acked = append(c.acked, packets...)
}

func (c *testAckCallback) OnPacketLost(pn quic.PacketNumber) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lost = append(c.lost, pn)
}

func TestInjectAckHook(t *testing.T) {
	// Start a simple QUIC server
	tlsConfig := generateTLSConfig()
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, &quic.Config{})
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Connect a client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicssh-test"},
	}
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLSConfig, &quic.Config{})
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	// Now set our ACK hook using the new API
	callback := &testAckCallback{}
	conn.SetAckHook(callback)

	t.Logf("SetAckHook succeeded!")
}

func generateTLSConfig() *tls.Config {
	cert, err := generateSelfSignedCert()
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quicssh-test"},
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
