package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

// SessionStreamHandler handles a QUIC stream with session layer protocol.
// It reads the initial frame to determine if this is a new session or resume.
type SessionStreamHandler struct {
	manager     *SessionManager
	idleTimeout time.Duration
	logf        logFunc
}

// NewSessionStreamHandler creates a new session stream handler.
func NewSessionStreamHandler(manager *SessionManager, idleTimeout time.Duration, logf logFunc) *SessionStreamHandler {
	return &SessionStreamHandler{
		manager:     manager,
		idleTimeout: idleTimeout,
		logf:        logf,
	}
}

// HandleStream handles a QUIC stream with the session layer protocol.
func (h *SessionStreamHandler) HandleStream(ctx context.Context, stream *quic.Stream, conn *quic.Conn, clientAddr string) (retErr error) {
	// Close the stream if we return an error
	defer func() {
		if retErr != nil {
			(*stream).Close()
		}
	}()

	streamID := stream.StreamID()
	h.logf("[stream %v from %s] Waiting for session frame...", streamID, clientAddr)

	// Read the first frame to determine session type
	frame, err := ReadFrame(stream, nil)
	if err != nil {
		return fmt.Errorf("failed to read session frame: %w", err)
	}

	switch f := frame.(type) {
	case *NewSessionFrame:
		return h.handleNewSession(ctx, stream, conn, f, clientAddr)
	case *ResumeSessionFrame:
		return h.handleResumeSession(ctx, stream, conn, f, clientAddr)
	default:
		return fmt.Errorf("unexpected frame type: %T", frame)
	}
}

func (h *SessionStreamHandler) handleNewSession(ctx context.Context, stream *quic.Stream, conn *quic.Conn, frame *NewSessionFrame, clientAddr string) error {
	streamID := stream.StreamID()
	h.logf("[stream %v from %s] NEW_SESSION: %s", streamID, clientAddr, frame.SessionID)

	// Create new session (connects to sshd)
	sess, err := h.manager.HandleNewSession(ctx, frame, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Store QUIC connection for stats access
	sess.SetQUICConn(conn)

	// Run the session data loop
	return h.runSessionLoop(stream, sess, clientAddr)
}

func (h *SessionStreamHandler) handleResumeSession(_ context.Context, stream *quic.Stream, conn *quic.Conn, frame *ResumeSessionFrame, clientAddr string) error {
	streamID := stream.StreamID()
	h.logf("[stream %v from %s] RESUME_SESSION: %s (lastSent=%d, lastRecv=%d)",
		streamID, clientAddr, frame.SessionID, frame.LastSentSeq, frame.LastRecvSeq)

	// Look up existing session
	sess, ack, err := h.manager.HandleResumeSession(frame, clientAddr)
	if err != nil {
		// Send a CloseFrame to inform the client that the session was not found
		// This allows the client to exit gracefully instead of retrying forever
		if errors.Is(err, ErrSessionNotFound) {
			closeFrame := &CloseFrame{Reason: "session not found"}
			if encErr := closeFrame.Encode(stream, nil); encErr != nil {
				h.logf("[stream %v from %s] Failed to send CloseFrame: %v", streamID, clientAddr, encErr)
			}
		}
		return fmt.Errorf("failed to resume session: %w", err)
	}

	// Store QUIC connection for stats access
	sess.SetQUICConn(conn)

	// Send RESUME_ACK
	if err := ack.Encode(stream, nil); err != nil {
		return fmt.Errorf("failed to send RESUME_ACK: %w", err)
	}
	h.logf("[stream %v from %s] Sent RESUME_ACK (lastRecv=%d, lastSent=%d)",
		streamID, clientAddr, ack.LastRecvSeq, ack.LastSentSeq)

	// Replay any unacknowledged data we have
	framesToReplay := sess.GetUnackedFrames(frame.LastRecvSeq)
	h.logf("[stream %v from %s] Replaying %d frames (client lastRecvSeq=%d, our lastSentSeq=%d)",
		streamID, clientAddr, len(framesToReplay), frame.LastRecvSeq, ack.LastSentSeq)
	encBuf := sess.EncodeBuffer()
	for i, df := range framesToReplay {
		if debugFrames {
			h.logf("[stream %v from %s]   replay[%d]: seq=%d %s", streamID, clientAddr, i, df.Seq, frameDigest(df.Payload))
		}
		if err := df.Encode(stream, encBuf); err != nil {
			return fmt.Errorf("failed to replay frame %d: %w", df.Seq, err)
		}
	}

	// Record the reconnect for stats
	sess.RecordReconnect()

	// Run the session data loop
	return h.runSessionLoop(stream, sess, clientAddr)
}

// runSessionLoop handles the bidirectional data flow for a session.
// It uses the session's context (not the caller's context) so that when the session
// is cleaned up via sess.cancel(), this loop will be canceled. The session context
// is a child of the QUIC connection context, so it will also be canceled if the
// QUIC connection dies.
//
// When a session resumes, HandleResumeSession cancels the old loop before
// returning, ensuring the new loop doesn't race with the old one.
func (h *SessionStreamHandler) runSessionLoop(stream *quic.Stream, sess *ServerSession, clientAddr string) error {
	streamID := stream.StreamID()

	// Store stream in session so it can be closed when session expires
	sess.SetStream(stream)
	defer sess.SetStream(nil) // Clear stream reference when loop ends

	loopCtx, cancel := context.WithCancel(sess.Context())
	loopDone := make(chan struct{})

	// Store the loop context so it can be canceled on session resume
	sess.SetLoopContext(cancel, loopDone)
	defer func() {
		cancel()
		sess.ClearLoopContext()
		close(loopDone)
	}()

	// Cleanup: if the loop exits with a fatal error (not just connection loss),
	// remove the session so it doesn't linger forever.
	// Non-fatal errors include:
	// - io.EOF: normal stream close
	// - context.Canceled: loop was canceled (e.g., during session resume)
	// - net.ErrClosed: QUIC connection died (client may reconnect)
	// - *quic.StreamError: stream canceled (e.g., CancelRead during resume)
	var loopErr error
	defer func() {
		if isFatalSessionError(loopErr) {
			h.logf("[stream %v] Session %s failed with error, removing: %v", streamID, sess, loopErr)
			h.manager.RemoveSession(sess.ID, fmt.Sprintf("session error: %v", loopErr))
		}
	}()

	errCh := make(chan error, 2)

	// Goroutine: QUIC stream -> sshd (with session layer)
	go func() {
		errCh <- h.streamToSSHD(loopCtx, stream, sess, clientAddr)
	}()

	// Goroutine: sshd -> QUIC stream (with session layer)
	go func() {
		errCh <- h.sshdToStream(loopCtx, stream, sess, clientAddr)
	}()

	// Wait for the first goroutine to finish, then cancel and wait for the second
	loopErr = <-errCh
	cancel() // Cancel the other goroutine

	// Set a deadline on the sshd connection to interrupt any blocked Read()
	// in sshdToStream. Without this, sshdToStream blocks forever when sshd
	// has no data to send (idle session), preventing the loop from exiting
	// and the deferred session cleanup from running.
	_ = sess.sshdConn.SetReadDeadline(time.Now())

	// Wait for the second goroutine to finish to ensure clean shutdown
	<-errCh

	// Clear the deadline so the sshd connection can be reused on resume
	_ = sess.sshdConn.SetReadDeadline(time.Time{})

	if isFatalSessionError(loopErr) {
		log.Printf("[stream %v] Session %s loop error: %v", streamID, sess, loopErr)
	}

	return loopErr
}

// streamToSSHD reads frames from QUIC stream and writes data to sshd.
// Both directions send application-level AckFrames so each side can clear
// its send buffer. The client sends AckFrames for server→client data, and
// this function sends AckFrames for client→server data.
func (h *SessionStreamHandler) streamToSSHD(ctx context.Context, stream *quic.Stream, sess *ServerSession, _ string) error {
	var framesSinceAck int
	var lastAckTime time.Time
	readBuf := make([]byte, MaxPayloadSize)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		frame, err := ReadFrame(stream, readBuf)
		if err != nil {
			return err
		}

		switch f := frame.(type) {
		case *DataFrame:
			if debugFrames {
				h.logf("[session %s] Received seq=%d %s", sess.ID, f.Seq, frameDigest(f.Payload))
			}

			// Check for duplicate or gap (pass logf for debug output)
			isNew, err := sess.HandleData(f, h.logf)
			if err != nil {
				// Gap detected - this shouldn't happen on the server side since
				// the client is responsible for replaying missed frames.
				// Log it and continue - the client will need to reconnect.
				h.logf("[session %s] Sequence gap detected: %v", sess.ID, err)
				return fmt.Errorf("sequence gap detected: %w", err)
			}
			if !isNew {
				continue
			}

			// Write to sshd
			h.logf("[session %s] Writing to sshd seq=%d", sess.ID, f.Seq)
			if _, err := sess.SSHDWriter().Write(f.Payload); err != nil {
				h.logf("[session %s] Failed to write to sshd: %v", sess.ID, err)
				return fmt.Errorf("failed to write to sshd: %w", err)
			}

			// Send ACK to client so it can clear its send buffer.
			// Without this, the client's buffer fills up during large uploads
			// (e.g., VS Code server tarball) and deadlocks.
			//
			// The ACK write must NOT block this goroutine. If the QUIC flow control
			// window in the server→client direction fills up, sshdToStream holds the
			// stream's write serialization lock waiting for it to open. If we tried to
			// write an ACK here (also a stream write), we would block and stop reading
			// from the stream, filling the client→server window too and deadlocking both
			// directions. A goroutine decouples the ACK write from the read loop.
			framesSinceAck++
			now := time.Now()
			if framesSinceAck >= ackBatchFrames || now.Sub(lastAckTime) >= ackBatchTimeout {
				seq := sess.LastRecvSeq()
				go func() {
					ack := &AckFrame{Seq: seq}
					ack.Encode(stream, nil) //nolint:errcheck // non-fatal; stream death detected by read/write loops
				}()
				framesSinceAck = 0
				lastAckTime = now
			}

			// Update activity
			h.manager.UpdateActivity(sess.ID)

		case *AckFrame:
			// Handle application-level ACK from client.
			// The client sends these after processing each DataFrame, allowing
			// us to safely clear the send buffer. This is the primary mechanism
			// for send buffer management (not QUIC-level ACKs, which fire before
			// the client application has read data from the QUIC stream buffer).
			sess.HandleAck(f)

		case *CloseFrame:
			h.logf("[session %s] Received CLOSE: %s", sess.ID, f.Reason)
			h.manager.RemoveSession(sess.ID, f.Reason)
			return nil

		default:
			return fmt.Errorf("unexpected frame type in data loop: %T", frame)
		}
	}
}

// sshdToStream reads data from sshd and writes frames to QUIC stream.
func (h *SessionStreamHandler) sshdToStream(ctx context.Context, stream *quic.Stream, sess *ServerSession, _ string) error {
	buf := make([]byte, 32*1024) // 32KB read buffer
	backpressureLogged := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Backpressure: wait if send buffer is full
		// This prevents us from reading more data from sshd than we can buffer
		for sess.SendBufferIsFull(len(buf)) {
			if !backpressureLogged {
				h.logf("[session %s] Send buffer full (%d bytes), applying backpressure on sshd",
					sess.ID, sess.SendBufferSize())
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
			h.logf("[session %s] Send buffer has space (%d bytes), resuming sshd reads",
				sess.ID, sess.SendBufferSize())
			backpressureLogged = false
		}

		n, err := sess.SSHDReader().Read(buf)
		if err != nil {
			// Check if context is canceled first - this takes priority.
			// CancelLoop() sets a deadline on the sshd connection to interrupt
			// this blocked read, so we check context here to exit cleanly.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			// Check if this is a timeout caused by CancelLoop setting a deadline
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				// Loop back to check context.Done() at the top
				continue
			}
			if err == io.EOF {
				// sshd closed the connection - send CLOSE frame
				h.logf("[session %s] sshd closed connection (EOF), sending CLOSE frame", sess.ID)
				closeFrame := &CloseFrame{Reason: "sshd closed"}
				if encErr := closeFrame.Encode(stream, nil); encErr != nil {
					h.logf("[session %s] Failed to send CLOSE frame: %v", sess.ID, encErr)
				}
				h.manager.RemoveSession(sess.ID, "sshd closed")
				return nil
			}
			h.logf("[session %s] sshd read error: %v", sess.ID, err)
			return fmt.Errorf("failed to read from sshd: %w", err)
		}

		if n > 0 {
			// Prepare and send data frame
			frame, err := sess.PrepareData(buf[:n])
			if err != nil {
				return fmt.Errorf("failed to prepare data: %w", err)
			}

			if debugFrames {
				h.logf("[session %s] Sending seq=%d %s", sess.ID, frame.Seq, frameDigest(frame.Payload))
			}

			if err := frame.Encode(stream, sess.EncodeBuffer()); err != nil {
				return fmt.Errorf("failed to send data frame: %w", err)
			}

			// Update activity
			h.manager.UpdateActivity(sess.ID)
		}
	}
}

// isGracefulClose returns true if the error indicates the remote peer
// gracefully closed the connection (QUIC error code 0). In this case the
// client will never reconnect, so the session should be cleaned up.
func isGracefulClose(err error) bool {
	var appErr *quic.ApplicationError
	return errors.As(err, &appErr) && appErr.Remote && appErr.ErrorCode == 0
}

// isFatalSessionError returns true if the error indicates that the session
// should be removed. This includes genuine application-level failures as well
// as graceful client shutdowns (error code 0). Returns false for errors that
// indicate connection loss or stream cancellation, where the client may reconnect.
func isFatalSessionError(err error) bool {
	if err == nil || err == io.EOF || err == context.Canceled {
		return false
	}
	// Client gracefully closed the connection (CloseWithError(0, ...)).
	// The client will never reconnect, so clean up the session.
	if isGracefulClose(err) {
		return true
	}
	// QUIC connection errors (ApplicationError, TransportError, IdleTimeoutError, etc.)
	// all unwrap to net.ErrClosed. These indicate connection loss, not application
	// failures — the client may reconnect and resume the session.
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	// Stream cancellation errors (from CancelRead during session resume).
	var streamErr *quic.StreamError
	return !errors.As(err, &streamErr)
}
