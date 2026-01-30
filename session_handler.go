package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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
	frame, err := ReadFrame(stream)
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

	// Install ACK hook on the QUIC connection
	sess.SetQUICConn(conn)

	// Run the session data loop
	return h.runSessionLoop(stream, sess, clientAddr)
}

func (h *SessionStreamHandler) handleResumeSession(ctx context.Context, stream *quic.Stream, conn *quic.Conn, frame *ResumeSessionFrame, clientAddr string) error {
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

	// Install ACK hook on the new QUIC connection
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
		// Record the replayed write for ACK tracking
		sess.RecordWrite(df.Seq)
	}

	// Run the session data loop
	return h.runSessionLoop(stream, sess, clientAddr)
}

// runSessionLoop handles the bidirectional data flow for a session.
// It uses the session's context (not the caller's context) so that when the session
// is cleaned up via sess.cancel(), this loop will be cancelled. The session context
// is a child of the QUIC connection context, so it will also be cancelled if the
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

	// Store the loop context so it can be cancelled on session resume
	sess.SetLoopContext(cancel, loopDone)
	defer func() {
		cancel()
		sess.ClearLoopContext()
		close(loopDone)
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

	// Wait for either goroutine to finish
	err := <-errCh
	cancel() // Cancel the other goroutine

	if err != nil && err != io.EOF && err != context.Canceled {
		log.Printf("[stream %v] Session %s loop error: %v", streamID, sess, err)
	}

	return err
}

// streamToSSHD reads frames from QUIC stream and writes data to sshd.
// ACKs are handled at the QUIC level via the ACK hook mechanism.
func (h *SessionStreamHandler) streamToSSHD(ctx context.Context, stream *quic.Stream, sess *ServerSession, clientAddr string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		frame, err := ReadFrame(stream)
		if err != nil {
			return err
		}

		switch f := frame.(type) {
		case *DataFrame:
			if debugFrames {
				h.logf("[session %s] Received seq=%d %s", sess.ID, f.Seq, frameDigest(f.Payload))
			}

			// Check for duplicate (pass logf for debug output)
			if !sess.HandleData(f, h.logf) {
				continue
			}

			// Write to sshd
			h.logf("[session %s] Writing to sshd seq=%d", sess.ID, f.Seq)
			if _, err := sess.SSHDWriter().Write(f.Payload); err != nil {
				h.logf("[session %s] Failed to write to sshd: %v", sess.ID, err)
				return fmt.Errorf("failed to write to sshd: %w", err)
			}

			// Update activity
			h.manager.UpdateActivity(sess.ID)

		case *AckFrame:
			// Handle ACK frames from old clients for backward compatibility
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
func (h *SessionStreamHandler) sshdToStream(ctx context.Context, stream *quic.Stream, sess *ServerSession, clientAddr string) error {
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

			// Record this write for QUIC ACK tracking
			sess.RecordWrite(frame.Seq)

			// Update activity
			h.manager.UpdateActivity(sess.ID)
		}
	}
}
