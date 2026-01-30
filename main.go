package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	cli "github.com/urfave/cli/v2"
)

// dumpGoroutines prints stack traces of all goroutines to stderr.
// This is triggered by SIGVTALRM and is useful for debugging hangs or deadlocks.
// Uses \r\n for line breaks because the terminal may be in raw mode.
func dumpGoroutines() {
	buf := make([]byte, 1<<20) // 1MB buffer
	n := runtime.Stack(buf, true)
	// Replace \n with \r\n for raw terminal mode
	stack := strings.ReplaceAll(string(buf[:n]), "\n", "\r\n")
	log.Printf("=== Goroutine Dump (%d goroutines) ===\r\n%s\r\n=== End Goroutine Dump ===",
		runtime.NumGoroutine(), stack)
}

// Buffer pool for readAndWrite to reduce GC pressure
var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

// keepAliveForIdleTimeout returns an appropriate keep-alive period for the given
// idle timeout. The keep-alive is scaled to 1/60th of the idle timeout, clamped
// between 5s (responsive for interactive sessions) and 30s (NAT-friendly).
func keepAliveForIdleTimeout(idleTimeout time.Duration) time.Duration {
	keepAlive := idleTimeout / 60
	if keepAlive < 5*time.Second {
		keepAlive = 5 * time.Second
	}
	if keepAlive > 30*time.Second {
		keepAlive = 30 * time.Second
	}
	return keepAlive
}

// newQUICConfig returns a QUIC config with standard settings for the given idle timeout.
func newQUICConfig(idleTimeout time.Duration, bufferSize int) *quic.Config {
	// Use buffer size for stream window, and 2x for connection window
	// to allow some headroom for multiple streams.
	streamWindow := uint64(bufferSize)
	connWindow := streamWindow * 2
	return &quic.Config{
		MaxIdleTimeout:                 idleTimeout,
		KeepAlivePeriod:                keepAliveForIdleTimeout(idleTimeout),
		InitialStreamReceiveWindow:     streamWindow / 8, // Start smaller, grow as needed
		MaxStreamReceiveWindow:         streamWindow,
		InitialConnectionReceiveWindow: connWindow / 8,
		MaxConnectionReceiveWindow:     connWindow,
		Allow0RTT:                      true, // Enable 0-RTT resumption for faster reconnects
	}
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
					&cli.DurationFlag{Name: "idle-timeout", Value: 30 * time.Second, Usage: "QUIC idle timeout (ignored when --session-layer is enabled)"},
					&cli.BoolFlag{Name: "insecure", Value: false, Usage: "generate and use self-signed certificate (insecure)"},
					&cli.StringFlag{Name: "cert", Value: "", Usage: "path to TLS certificate file"},
					&cli.StringFlag{Name: "key", Value: "", Usage: "path to TLS private key file"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Value: false, Usage: "enable verbose logging"},
					&cli.BoolFlag{Name: "session-layer", Value: false, Usage: "enable session layer for connection resilience"},
					&cli.DurationFlag{Name: "session-timeout", Value: 30 * time.Minute, Usage: "session timeout for reconnection"},
					&cli.IntFlag{Name: "max-sessions", Value: 1024, Usage: "maximum number of concurrent sessions (0 = unlimited)"},
					&cli.IntFlag{Name: "buffer-size", Value: DefaultBufferSize, Usage: "maximum size of send buffer per session in bytes"},
				},
				Action: server,
			},
			{
				Name: "client",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "addr", Value: "localhost:4242", Usage: "address of server"},
					&cli.StringFlag{Name: "localaddr", Value: ":0", Usage: "source address of UDP packets"},
					&cli.DurationFlag{Name: "idle-timeout", Value: 2 * time.Minute, Usage: "QUIC idle timeout"},
					&cli.BoolFlag{Name: "insecure", Value: false, Usage: "skip TLS certificate verification (insecure)"},
					&cli.StringFlag{Name: "servercert", Value: "", Usage: "path to server's TLS certificate for verification"},
					&cli.BoolFlag{Name: "skip-verify-hostname", Value: false, Usage: "skip hostname verification (still verifies certificate)"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Value: false, Usage: "enable verbose logging"},
					&cli.IntFlag{Name: "ssh-port", Value: 22, Usage: "SSH port for direct connection when bypassing QUIC"},
					&cli.BoolFlag{Name: "no-passthrough", Value: false, Usage: "disable automatic passthrough for bulk transfers (scp, rsync, sftp)"},
					&cli.DurationFlag{Name: "path-check-interval", Value: 10 * time.Second, Usage: "interval for checking IP changes for path migration (0 to disable)"},
					&cli.BoolFlag{Name: "session-layer", Value: false, Usage: "enable session layer for connection resilience"},
					&cli.IntFlag{Name: "buffer-size", Value: DefaultBufferSize, Usage: "maximum size of send buffer per session in bytes"},
				},
				Action: client,
			},
			{
				Name:  "patch-vscode-remote-ssh",
				Usage: "Patch VS Code Remote-SSH extension to increase timeout values for use with quicssh",
				Description: `This command patches the VS Code Remote-SSH extension to increase two timeout
values that cause connections to fail despite quicssh keeping them alive:

  1. ExecServerCache ping timeout (3 seconds -> 25 hours)
  2. Local server dead man's switch (5 seconds -> 25 hours)

The original files are backed up with a .orig extension so you can easily revert.
Use 'unpatch-vscode-remote-ssh' to restore the original files.

Note: You will need to re-run this command after VS Code updates the extension.`,
				Action: patchVSCodeRemoteSSH,
			},
			{
				Name:   "unpatch-vscode-remote-ssh",
				Usage:  "Restore original VS Code Remote-SSH extension files from backups",
				Action: unpatchVSCodeRemoteSSH,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// readAndWrite copies data from r to w, setting deadlines on QUIC streams
// to prevent indefinite blocking when the network path is temporarily unavailable.
// This allows the connection to survive VPN hiccups as long as they're shorter than
// the idle timeout.
// If onNetworkTrouble is provided, it will be called when network issues are detected.
func readAndWrite(ctx context.Context, r io.Reader, w io.Writer, idleTimeout time.Duration, logf logFunc, onNetworkTrouble ...networkTroubleCallback) <-chan error {
	c := make(chan error)
	go func() {
		defer close(c)

		// Get buffer from pool to reduce GC pressure
		bufp := bufPool.Get().(*[]byte)
		buf := *bufp
		defer bufPool.Put(bufp)

		// Check if reader/writer support deadlines (QUIC streams do)
		rDeadliner, rHasDeadline := r.(deadliner)
		wDeadliner, wHasDeadline := w.(deadliner)

		// Track when we started waiting for network to recover
		var networkDownSince time.Time
		var troubleSignaled bool // only signal once per trouble period

		// Helper to signal network trouble
		signalTrouble := func() {
			if !troubleSignaled && len(onNetworkTrouble) > 0 {
				troubleSignaled = true
				onNetworkTrouble[0]()
			}
		}

		logf("[%T->%T] Starting read/write loop (idleTimeout=%v, rHasDeadline=%v, wHasDeadline=%v)",
			r, w, idleTimeout, rHasDeadline, wHasDeadline)

		for {
			// Set read deadline if supported
			if rHasDeadline {
				// Use a shorter deadline for reads to allow periodic checking
				// Use 30 seconds or half the idle timeout, whichever is smaller
				readTimeout := 30 * time.Second
				if idleTimeout/2 < readTimeout {
					readTimeout = idleTimeout / 2
				}
				rDeadliner.SetReadDeadline(time.Now().Add(readTimeout))
			}

			nr, err := r.Read(buf)

			if nr > 0 {
				logf("[%T->%T] Read %d bytes", r, w, nr)
				// We got data, network is working
				if !networkDownSince.IsZero() {
					logf("[%T->%T] Network recovered after %v", r, w, time.Since(networkDownSince))
				}
				networkDownSince = time.Time{}
				troubleSignaled = false // reset for next trouble period

				// Set write deadline if supported
				if wHasDeadline {
					wDeadliner.SetWriteDeadline(time.Now().Add(idleTimeout))
				}

				nw, werr := w.Write(buf[:nr])
				if werr != nil {
					logf("[%T->%T] Write error: %v (type: %T)", r, w, werr, werr)
					// Check if it's a timeout error
					if isTimeoutError(werr) {
						logf("[%T->%T] Write timeout detected", r, w)
						// Write timed out - network might be down
						if networkDownSince.IsZero() {
							networkDownSince = time.Now()
							logf("[%T->%T] Network appears down, starting timer", r, w)
						}
						// Signal network trouble to trigger path migration
						signalTrouble()
						// Check if we've exceeded the idle timeout
						downFor := time.Since(networkDownSince)
						if downFor >= idleTimeout {
							c <- fmt.Errorf("network unavailable for %v (exceeds idle timeout): %w", downFor, werr)
							return
						}
						logf("[%T->%T] Network down for %v, continuing to retry", r, w, downFor)
						// Otherwise, continue trying
						continue
					}
					c <- werr
					return
				}
				logf("[%T->%T] Wrote %d bytes", r, w, nw)
				if nw != nr {
					c <- io.ErrShortWrite
					return
				}
			}

			if err != nil {
				logf("[%T->%T] Read error: %v (type: %T)", r, w, err, err)
				// Check if it's a timeout error (deadline exceeded)
				if isTimeoutError(err) {
					logf("[%T->%T] Read timeout (expected during idle/network hiccups)", r, w)
					// Read timed out - this could be normal idle or network trouble
					// If we already know the network is down (from write failures),
					// signal trouble to trigger path migration
					if !networkDownSince.IsZero() {
						signalTrouble()
					}
					// Check if context is cancelled
					select {
					case <-ctx.Done():
						logf("[%T->%T] Context cancelled: %v", r, w, ctx.Err())
						c <- ctx.Err()
						return
					default:
						// Continue waiting - the network might come back
						continue
					}
				}

				// Check for context cancellation
				select {
				case <-ctx.Done():
					logf("[%T->%T] Context cancelled: %v", r, w, ctx.Err())
					c <- ctx.Err()
				default:
					logf("[%T->%T] Fatal read error, exiting: %v", r, w, err)
					c <- err
				}
				return
			}
		}
	}()
	return c
}

// deadliner is an interface for types that support setting deadlines
type deadliner interface {
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// isTimeoutError checks if an error is a timeout error (deadline exceeded)
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// Check for net.Error timeout
	if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
		return true
	}
	// Also check for os.ErrDeadlineExceeded which some implementations return
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	return false
}

// logFunc is a function type for logging
type logFunc func(format string, v ...interface{})

// createLogFunc creates a logging function based on --verbose flag and QUICSSH_VERBOSE env var.
// If --verbose is set, logs to stderr.
// If QUICSSH_VERBOSE=1, logs to stderr.
// If QUICSSH_VERBOSE starts with "/", logs to that file path.
// Returns the logFunc and an optional file that should be closed when done.
func createLogFunc(c *cli.Context) (logFunc, *os.File) {
	// Check --verbose flag first (takes precedence)
	if c.Bool("verbose") {
		return func(format string, v ...interface{}) {
			log.Printf(format, v...)
		}, nil
	}

	// Check QUICSSH_VERBOSE env var
	verboseEnv := os.Getenv("QUICSSH_VERBOSE")
	if verboseEnv == "" {
		return func(format string, v ...interface{}) {}, nil
	}

	if verboseEnv == "1" {
		return func(format string, v ...interface{}) {
			log.Printf(format, v...)
		}, nil
	}

	if strings.HasPrefix(verboseEnv, "/") {
		// Open file for logging
		f, err := os.OpenFile(verboseEnv, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Warning: failed to open log file %s: %v", verboseEnv, err)
			return func(format string, v ...interface{}) {}, nil
		}
		logger := log.New(f, "", log.LstdFlags)
		return func(format string, v ...interface{}) {
			logger.Printf(format, v...)
		}, f
	}

	// Unknown value, ignore
	return func(format string, v ...interface{}) {}, nil
}

// debugFrames is true if per-frame debug logging is enabled via QUICSSH_DEBUG_FRAMES=1.
var debugFrames = os.Getenv("QUICSSH_DEBUG_FRAMES") == "1"

// networkTroubleCallback is called when network issues are detected (e.g., repeated timeouts).
// This allows the caller to trigger path migration or other recovery mechanisms.
type networkTroubleCallback func()
