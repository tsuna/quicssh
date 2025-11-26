package main

import (
	"context"
	"crypto/tls"
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

	config := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicssh"},
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
	session, err := quic.Dial(ctx, conn, udpAddr, config, &quic.Config{MaxIdleTimeout: c.Duration("idletimeout"), KeepAlivePeriod: 5 * time.Second})
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
