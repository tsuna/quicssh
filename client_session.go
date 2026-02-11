package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// ackBatchFrames is the maximum number of received frames before sending an ACK.
	// At the maximum frame size (64KB), 64 frames = 4MB of unACKed data, leaving
	// 12MB of headroom in the default 16MB send buffer for ACK delivery latency.
	ackBatchFrames = 64
	// ackBatchTimeout is the maximum time to wait before sending an ACK.
	ackBatchTimeout = 300 * time.Millisecond
)

// ClientSession manages the client-side session state and handles
// reconnection with the session layer protocol.
type ClientSession struct {
	*Session // Embedded session state

	mu sync.Mutex

	// Connection state
	connected bool
	stream    io.ReadWriteCloser
	quicConn  *quic.Conn // stored for stats access and graceful close

	// ACK batching state: instead of ACKing every frame, we batch ACKs
	// and send when either the frame count or time threshold is reached.
	framesSinceAck int
	lastAckTime    time.Time

	// Client process info (for logging on server side)
	clientPID          uint32
	grandparentProcess string

	// Logging
	logf logFunc
}

// NewClientSession creates a new client session.
func NewClientSession(bufferSize int, logf logFunc) (*ClientSession, error) {
	sess, err := NewSession(bufferSize)
	if err != nil {
		return nil, err
	}
	return &ClientSession{
		Session:            sess,
		clientPID:          uint32(os.Getpid()),
		grandparentProcess: getGrandparentProcessName(),
		logf:               logf,
	}, nil
}

// SetQUICConn stores the QUIC connection for stats access and graceful close.
// This should be called after establishing/resuming a connection.
func (cs *ClientSession) SetQUICConn(conn *quic.Conn) {
	cs.mu.Lock()
	cs.quicConn = conn
	cs.mu.Unlock()
}

// CloseQUIC tries to close the underlying QUIC connection gracefully.
// This should be called when the client is shutting down to notify the server.
func (cs *ClientSession) CloseQUIC(reason string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.quicConn != nil {
		cs.logf("[ClientSession] Closing QUIC connection: %s", reason)
		if err := cs.quicConn.CloseWithError(0, reason); err != nil {
			cs.logf("[ClientSession] Error closing QUIC connection: %v", err)
		}
	}
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
func (cs *ClientSession) SendData(_ context.Context, payload []byte) error {
	cs.mu.Lock()
	if !cs.connected {
		cs.mu.Unlock()
		return fmt.Errorf("not connected")
	}
	frame, err := cs.PrepareData(payload)
	if err != nil {
		cs.mu.Unlock()
		return err
	}
	// Capture stream and encode buffer, then release the lock BEFORE writing.
	// The QUIC stream has its own internal mutex for write serialization.
	// Holding cs.mu during the write would deadlock: if the QUIC flow control
	// window is full, this write blocks, preventing the receiver goroutine from
	// calling SendAck (which needs cs.mu), which prevents reading from the
	// stream, which prevents the flow control window from opening.
	stream := cs.stream
	encBuf := cs.EncodeBuffer()
	cs.mu.Unlock()

	if err := frame.Encode(stream, encBuf); err != nil {
		cs.mu.Lock()
		cs.connected = false
		cs.mu.Unlock()
		return fmt.Errorf("failed to send DATA: %w", err)
	}

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

// SendAck notifies the server of the client's receive progress so it can clear
// its send buffer. To reduce overhead, ACKs are batched: an AckFrame is only
// sent after every ackBatchFrames frames or ackBatchTimeout, whichever comes first.
// The AckFrame is cumulative — a single ACK with lastRecvSeq=N covers all frames
// up to and including N.
// This should be called after successfully processing each received DataFrame.
func (cs *ClientSession) SendAck() error {
	cs.mu.Lock()
	if !cs.connected || cs.stream == nil {
		cs.mu.Unlock()
		return nil
	}

	lastRecvSeq := cs.LastRecvSeq()
	if lastRecvSeq == 0 {
		cs.mu.Unlock()
		return nil // Nothing received yet
	}

	cs.framesSinceAck++

	// Send ACK when either threshold is reached
	now := time.Now()
	if cs.framesSinceAck < ackBatchFrames && now.Sub(cs.lastAckTime) < ackBatchTimeout {
		cs.mu.Unlock()
		return nil
	}

	cs.framesSinceAck = 0
	cs.lastAckTime = now
	stream := cs.stream
	cs.mu.Unlock()

	// Write without holding cs.mu to avoid deadlock (see SendData comment).
	ack := &AckFrame{Seq: lastRecvSeq}
	return ack.Encode(stream, nil)
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
	cs.logf("[ClientSession] Disconnect() called, connected=%v, stream=%v", cs.connected, cs.stream != nil)
	cs.connected = false
	if cs.stream != nil {
		cs.stream.Close()
		cs.stream = nil
		cs.logf("[ClientSession] Stream closed")
	}
}

// DumpStats logs the current session statistics.
func (cs *ClientSession) DumpStats() {
	cs.mu.Lock()
	now := time.Now()
	connected := cs.connected
	var connStats quic.ConnectionStats
	if quicConn := cs.quicConn; quicConn != nil {
		connStats = quicConn.ConnectionStats()
	}
	cs.mu.Unlock()

	lastSent, lastRecv := cs.ResumeState()
	sendBufSize := cs.sendBuffer.Size()
	sendBufFrames := cs.sendBuffer.Len()
	sendBufMinSeq := cs.sendBuffer.MinSeq()
	sendBufMaxSeq := cs.sendBuffer.MaxSeq()
	reconnectCount, lastReconnect := cs.ReconnectStats()

	// Always log to stderr regardless of --verbose since this is triggered by SIGUSR1.
	// Use \r\n because the terminal may be in raw mode (interactive SSH session),
	// where \n alone doesn't return the cursor to the beginning of the line.
	// Print in a single write to avoid interleaving with SSH data.
	fmt.Fprintf(os.Stderr,
		"\r\n=== Client Session Dump @ %s ===\r\n"+
			"  SessionID: %s\r\n"+
			"  ClientPID: %d (GrandparentProcess: %q)\r\n"+
			"  Connected: %v, Reconnects: %d (last: %s)\r\n"+
			"  SendBuffer: %d bytes / %d frames (seq %d-%d)\r\n"+
			"  LastSentSeq: %d\r\n"+
			"  LastRecvSeq: %d\r\n"+
			"  QUIC Stats: RTT=%v (min=%v, σ=%v), sent=%s/%dpkts, recv=%s/%dpkts, lost=%s/%dpkts\r\n"+
			"=== End Session Dump ===\r\n",
		now.Format("2006/01/02 15:04:05"),
		cs.ID, cs.clientPID, cs.grandparentProcess,
		connected, reconnectCount, timeAgo(lastReconnect, now),
		sendBufSize, sendBufFrames, sendBufMinSeq, sendBufMaxSeq,
		lastSent, lastRecv,
		connStats.SmoothedRTT.Round(time.Millisecond),
		connStats.MinRTT.Round(time.Millisecond),
		connStats.MeanDeviation.Round(time.Millisecond),
		fmtBytes(connStats.BytesSent), connStats.PacketsSent,
		fmtBytes(connStats.BytesReceived), connStats.PacketsReceived,
		fmtBytes(connStats.BytesLost), connStats.PacketsLost)
}
