package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/quic-go/quic-go"
)

// ClientSession manages the client-side session state and handles
// reconnection with the session layer protocol.
type ClientSession struct {
	*Session // Embedded session state

	mu sync.Mutex

	// Connection state
	connected bool
	stream    io.ReadWriteCloser

	// Client process info (for logging on server side)
	clientPID          uint32
	grandparentProcess string

	// ACK tracking for QUIC-level ACKs
	ackTracker *AckTracker

	// Logging
	logf logFunc
}

// NewClientSession creates a new client session.
func NewClientSession(bufferSize int, logf logFunc) (*ClientSession, error) {
	sess, err := NewSession(bufferSize)
	if err != nil {
		return nil, err
	}
	cs := &ClientSession{
		Session:            sess,
		clientPID:          uint32(os.Getpid()),
		grandparentProcess: getGrandparentProcessName(),
		logf:               logf,
	}
	// Create ACK tracker that clears our send buffer when QUIC ACKs packets
	// Client doesn't have a session timeout, so no onActivity callback needed
	cs.ackTracker = NewAckTracker(
		func(upToSeq uint64) {
			cs.Session.HandleAck(&AckFrame{Seq: upToSeq})
			cs.logf("[ClientSession] QUIC ACK cleared buffer up to seq=%d", upToSeq)
		},
		nil, // no activity tracking on client
	)
	return cs, nil
}

// SetQUICConn installs the ACK hook on the QUIC connection.
// This should be called after establishing/resuming a connection.
func (cs *ClientSession) SetQUICConn(conn *quic.Conn) {
	// Clear old tracking state from previous connection
	cs.ackTracker.Clear()
	// Install ACK hook
	conn.SetAckHook(cs.ackTracker)
	cs.logf("[ClientSession] ACK hook installed on QUIC connection")
}

// RecordWrite records a frame write for QUIC ACK tracking.
// This should be called after writing a frame to the stream.
func (cs *ClientSession) RecordWrite(seq uint64) {
	cs.ackTracker.RecordWrite(seq)
}

// Connect performs the initial connection handshake (NEW_SESSION).
func (cs *ClientSession) Connect(stream io.ReadWriteCloser) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.stream = stream

	// Send NEW_SESSION frame with client process info
	frame := &NewSessionFrame{
		SessionID:          cs.ID,
		ClientPID:          cs.clientPID,
		GrandparentProcess: cs.grandparentProcess,
	}
	if err := frame.Encode(stream, nil); err != nil {
		return fmt.Errorf("failed to send NEW_SESSION: %w", err)
	}

	cs.connected = true
	cs.logf("[ClientSession] Connected with session ID: %s (pid=%d, grandparent=%q)",
		cs.ID, cs.clientPID, cs.grandparentProcess)
	return nil
}

// Resume performs the reconnection handshake (RESUME_SESSION).
// Returns the frames that need to be replayed.
func (cs *ClientSession) Resume(stream io.ReadWriteCloser) ([]DataFrame, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.stream = stream

	lastSentSeq, lastRecvSeq := cs.ResumeState()

	// Send RESUME_SESSION frame
	frame := &ResumeSessionFrame{
		SessionID:   cs.ID,
		LastSentSeq: lastSentSeq,
		LastRecvSeq: lastRecvSeq,
	}
	if err := frame.Encode(stream, nil); err != nil {
		return nil, fmt.Errorf("failed to send RESUME_SESSION: %w", err)
	}

	cs.logf("[ClientSession] Sent RESUME_SESSION (lastSent=%d, lastRecv=%d)", lastSentSeq, lastRecvSeq)

	// Read RESUME_ACK
	respFrame, err := ReadFrame(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read RESUME_ACK: %w", err)
	}

	// Check if server sent a CloseFrame (e.g., session not found after server restart)
	if _, ok := respFrame.(*CloseFrame); ok {
		return nil, ErrSessionNotFound
	}

	ack, ok := respFrame.(*ResumeAckFrame)
	if !ok {
		return nil, fmt.Errorf("expected RESUME_ACK, got %T", respFrame)
	}

	cs.logf("[ClientSession] Received RESUME_ACK (serverLastRecv=%d, serverLastSent=%d)",
		ack.LastRecvSeq, ack.LastSentSeq)

	// Get frames to replay (everything after what server received)
	framesToReplay := cs.GetUnackedFrames(ack.LastRecvSeq)

	// Note: We do NOT update lastRecvSeq here. The server will replay frames
	// from our lastRecvSeq+1 to serverLastSentSeq, and we need to receive them
	// normally through HandleData(). The serverLastSentSeq is informational only.

	cs.connected = true
	cs.logf("[ClientSession] Resume complete, %d frames to replay, expecting server to replay %d frames",
		len(framesToReplay), ack.LastSentSeq-lastRecvSeq)

	return framesToReplay, nil
}

// SendData sends data through the session layer.
// The data is buffered for potential replay on reconnect.
func (cs *ClientSession) SendData(ctx context.Context, payload []byte) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if !cs.connected {
		return fmt.Errorf("not connected")
	}

	frame, err := cs.PrepareData(payload)
	if err != nil {
		return err
	}

	if err := frame.Encode(cs.stream, cs.EncodeBuffer()); err != nil {
		cs.connected = false
		return fmt.Errorf("failed to send DATA: %w", err)
	}

	// Record this write for QUIC ACK tracking
	cs.ackTracker.RecordWrite(frame.Seq)

	return nil
}

// ReadFrame reads the next frame from the stream.
func (cs *ClientSession) ReadFrame() (Frame, error) {
	cs.mu.Lock()
	stream := cs.stream
	cs.mu.Unlock()

	if stream == nil {
		return nil, fmt.Errorf("not connected")
	}

	return ReadFrame(stream)
}

// IsConnected returns whether the session is currently connected.
func (cs *ClientSession) IsConnected() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.connected
}

// Disconnect marks the session as disconnected.
func (cs *ClientSession) Disconnect() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.connected = false
	if cs.stream != nil {
		cs.stream.Close()
		cs.stream = nil
	}
}

// DumpStats logs the current session statistics.
func (cs *ClientSession) DumpStats() {
	cs.mu.Lock()
	connected := cs.connected
	cs.mu.Unlock()

	lastSent, lastRecv := cs.Session.ResumeState()
	sendBufSize := cs.Session.sendBuffer.Size()
	sendBufFrames := cs.Session.sendBuffer.Len()
	sendBufMinSeq := cs.Session.sendBuffer.MinSeq()
	sendBufMaxSeq := cs.Session.sendBuffer.MaxSeq()
	pendingWrites, ackedPackets, highestAcked := cs.ackTracker.Stats()

	// Always log to stderr regardless of --verbose since this is triggered by SIGUSR1.
	// Use \r\n because the terminal may be in raw mode (interactive SSH session),
	// where \n alone doesn't return the cursor to the beginning of the line.
	// Print in a single write to avoid interleaving with SSH data.
	fmt.Fprintf(os.Stderr,
		"\r\n=== Client Session Dump ===\r\n"+
			"  SessionID: %s\r\n"+
			"  ClientPID: %d\r\n"+
			"  GrandparentProcess: %q\r\n"+
			"  Connected: %v\r\n"+
			"  SendBuffer: %d bytes / %d frames (seq %d-%d)\r\n"+
			"  LastSentSeq: %d\r\n"+
			"  LastRecvSeq: %d\r\n"+
			"  QUIC ACKs: pending=%d, acked=%d, highest=%d\r\n"+
			"=== End Session Dump ===\r\n",
		cs.Session.ID, cs.clientPID, cs.grandparentProcess, connected,
		sendBufSize, sendBufFrames, sendBufMinSeq, sendBufMaxSeq,
		lastSent, lastRecv, pendingWrites, ackedPackets, highestAcked)
}
