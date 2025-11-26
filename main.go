package main

import (
	"context"
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"

	cli "github.com/urfave/cli/v2"
)

// Buffer pool for readAndWrite to reduce GC pressure
var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

func main() {
	build, _ := debug.ReadBuildInfo()
	app := &cli.App{
		Version: build.Main.Version,
		Usage:   "Client and server parts to proxy SSH (TCP) over UDP using QUIC transport",
		Commands: []*cli.Command{
			{
				Name: "server",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "bind", Value: "localhost:4242", Usage: "bind address"},
					&cli.StringFlag{Name: "sshdaddr", Value: "localhost:22", Usage: "target address of sshd"},
					&cli.DurationFlag{Name: "idletimeout", Value: 30 * time.Second, Usage: "idle timeout"},
					&cli.BoolFlag{Name: "insecure", Value: false, Usage: "generate and use self-signed certificate (insecure)"},
					&cli.StringFlag{Name: "cert", Value: "", Usage: "path to TLS certificate file"},
					&cli.StringFlag{Name: "key", Value: "", Usage: "path to TLS private key file"},
				},
				Action: server,
			},
			{
				Name: "client",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "addr", Value: "localhost:4242", Usage: "address of server"},
					&cli.StringFlag{Name: "localaddr", Value: ":0", Usage: "source address of UDP packets"},
					&cli.DurationFlag{Name: "idletimeout", Value: 30 * time.Second, Usage: "idle timeout"},
					&cli.BoolFlag{Name: "insecure", Value: false, Usage: "skip TLS certificate verification (insecure)"},
					&cli.StringFlag{Name: "servercert", Value: "", Usage: "path to server's TLS certificate for verification"},
					&cli.BoolFlag{Name: "skip-verify-hostname", Value: false, Usage: "skip hostname verification (still verifies certificate)"},
				},
				Action: client,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func readAndWrite(ctx context.Context, r io.Reader, w io.Writer) <-chan error {
	c := make(chan error)
	go func() {
		defer close(c)

		// Get buffer from pool to reduce GC pressure
		bufp := bufPool.Get().(*[]byte)
		buf := *bufp
		defer bufPool.Put(bufp)

		for {
			nr, err := r.Read(buf)
			if nr > 0 {
				// Write directly instead of using io.Copy with bytes.NewReader
				// which was creating unnecessary allocations and copying
				nw, werr := w.Write(buf[:nr])
				if werr != nil {
					c <- werr
					return
				}
				if nw != nr {
					c <- io.ErrShortWrite
					return
				}
			}
			if err != nil {
				// Check for context cancellation
				select {
				case <-ctx.Done():
					c <- ctx.Err()
				default:
					c <- err
				}
				return
			}
		}
	}()
	return c
}
