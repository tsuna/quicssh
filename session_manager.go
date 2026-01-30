package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

// ServerSession represents a session on the server side.
// It maintains the connection to sshd and session state across QUIC reconnects.
type ServerSession struct {
	*Session // Embedded session state (includes mutex)

	// Remote client address (for logging)
	remoteAddr string

	// Client process info (for logging/debugging)
	clientPID          uint32
	grandparentProcess string

	// Connection to local sshd
	sshdConn net.Conn

	// Current QUIC stream (for sending CloseFrame when session expires)
	stream *quic.Stream

	// Current QUIC connection (for stats in SIGUSR1 dump)
	quicConn *quic.Conn

	// Last activity time for timeout
	lastActivity time.Time

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Loop cancellation for handling session resume.
	// When a session resumes, we need to cancel the old runSessionLoop
	// before starting a new one to avoid race conditions.
	loopCancel context.CancelFunc
	loopDone   chan struct{}

	// ACK tracking for QUIC-level ACKs
	ackTracker *AckTracker

	// Logging
	logf logFunc
}

// String returns a string representation of the session for logging.
func (ss *ServerSession) String() string {
	return fmt.Sprintf("%s/%s", ss.ID, ss.remoteAddr)
}

// Context returns the session's context, which is cancelled when the session is closed.
func (ss *ServerSession) Context() context.Context {
	return ss.ctx
}

// SetStream sets the current QUIC stream for the session.
// This is used to send a CloseFrame when the session expires.
func (ss *ServerSession) SetStream(stream *quic.Stream) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.stream = stream
}

// CloseStream sends a CloseFrame on the current stream and closes it.
func (ss *ServerSession) CloseStream(reason string) {
	ss.mu.Lock()
	stream := ss.stream
	ss.stream = nil
	ss.mu.Unlock()

	if stream != nil {
		// Try to send a CloseFrame so the client knows why the session ended
		closeFrame := &CloseFrame{Reason: reason}
		// Use a short deadline to avoid blocking forever
		_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = closeFrame.Encode(stream, nil)
		stream.Close()
	}
}

// CancelLoop cancels the current runSessionLoop (if any) and waits for it to exit.
// This must be called before starting a new runSessionLoop to avoid race conditions.
func (ss *ServerSession) CancelLoop() {
	ss.mu.Lock()
	cancel := ss.loopCancel
	done := ss.loopDone
	ss.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		// Wait for the old loop to exit with a timeout
		select {
		case <-done:
			ss.logf("[session %s] Old loop exited cleanly", ss.ID)
		case <-time.After(5 * time.Second):
			ss.logf("[session %s] Timeout waiting for old loop to exit", ss.ID)
		}
	}
}

// SetLoopContext stores the loop's cancel function and done channel.
// This is called at the start of runSessionLoop.
func (ss *ServerSession) SetLoopContext(cancel context.CancelFunc, done chan struct{}) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.loopCancel = cancel
	ss.loopDone = done
}

// ClearLoopContext clears the loop context when the loop exits.
func (ss *ServerSession) ClearLoopContext() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.loopCancel = nil
	ss.loopDone = nil
}

// SessionManager manages all active sessions on the server.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[SessionID]*ServerSession

	// Configuration
	sshdAddr       string        // Address of local sshd (e.g., "127.0.0.1:22")
	sessionTimeout time.Duration // How long to keep session alive without activity
	maxSessions    int           // Maximum number of concurrent sessions (0 = unlimited)
	bufferSize     int           // Maximum size of send buffer per session

	logf logFunc
}

// NewSessionManager creates a new session manager and starts the cleanup loop.
func NewSessionManager(ctx context.Context, sshdAddr string, sessionTimeout time.Duration, maxSessions int, bufferSize int, logf logFunc) *SessionManager {
	m := &SessionManager{
		sessions:       make(map[SessionID]*ServerSession),
		sshdAddr:       sshdAddr,
		sessionTimeout: sessionTimeout,
		maxSessions:    maxSessions,
		bufferSize:     bufferSize,
		logf:           logf,
	}
	go m.startCleanupLoop(ctx)
	return m
}

// HandleNewSession creates a new session and connects to sshd.
func (m *SessionManager) HandleNewSession(ctx context.Context, frame *NewSessionFrame, remoteAddr string) (*ServerSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session already exists
	if _, exists := m.sessions[frame.SessionID]; exists {
		return nil, fmt.Errorf("session %s already exists", frame.SessionID)
	}

	// Evict oldest session if at capacity
	if m.maxSessions > 0 && len(m.sessions) >= m.maxSessions {
		m.evictOldestLocked()
	}

	// Connect to local sshd
	sshdConn, err := net.Dial("tcp", m.sshdAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sshd at %s: %w", m.sshdAddr, err)
	}

	sessionCtx, cancel := context.WithCancel(ctx)

	sess := &ServerSession{
		Session:            NewSessionWithID(frame.SessionID, m.bufferSize),
		remoteAddr:         remoteAddr,
		clientPID:          frame.ClientPID,
		grandparentProcess: frame.GrandparentProcess,
		sshdConn:           sshdConn,
		lastActivity:       time.Now(),
		ctx:                sessionCtx,
		cancel:             cancel,
		logf:               m.logf,
	}

	// Create ACK tracker that clears our send buffer when QUIC ACKs packets
	// and updates lastActivity on any QUIC activity (including keep-alives)
	sess.ackTracker = NewAckTracker(
		func(upToSeq uint64) {
			removed, minSeq, maxSeq := sess.Session.HandleAck(&AckFrame{Seq: upToSeq})
			if removed > 0 {
				sess.logf("[ServerSession %s] QUIC ACK cleared %d frames (seq %d-%d) up to seq=%d",
					sess, removed, minSeq, maxSeq, upToSeq)
			}
		},
		func() {
			// Update lastActivity on any QUIC activity (including keep-alive ACKs)
			sess.mu.Lock()
			sess.lastActivity = time.Now()
			sess.mu.Unlock()
		},
	)

	m.sessions[frame.SessionID] = sess
	m.logf("[SessionManager] New session created: %s from %q (pid=%d, total: %d)",
		sess, sess.grandparentProcess, sess.clientPID, len(m.sessions))

	return sess, nil
}

// evictOldestLocked removes the session with the oldest lastActivity.
// Must be called with m.mu held.
func (m *SessionManager) evictOldestLocked() {
	var oldestID SessionID
	var oldestTime time.Time
	first := true

	for id, sess := range m.sessions {
		if first || sess.lastActivity.Before(oldestTime) {
			oldestID = id
			oldestTime = sess.lastActivity
			first = false
		}
	}

	if !first {
		if sess, exists := m.sessions[oldestID]; exists {
			m.logf("[SessionManager] Evicting oldest session %s (last activity: %v) to make room", sess, oldestTime)
			sess.cancel()
			sess.sshdConn.Close()
			delete(m.sessions, oldestID)
		}
	}
}

// HandleResumeSession looks up an existing session and returns resume state.
// It also cancels any existing runSessionLoop to prevent race conditions.
func (m *SessionManager) HandleResumeSession(frame *ResumeSessionFrame, remoteAddr string) (*ServerSession, *ResumeAckFrame, error) {
	m.mu.Lock()

	sess, exists := m.sessions[frame.SessionID]
	if !exists {
		m.mu.Unlock()
		return nil, nil, ErrSessionNotFound
	}

	oldAddr := sess.remoteAddr
	sess.remoteAddr = remoteAddr
	sess.lastActivity = time.Now()

	// Build resume ACK with our state
	ack := &ResumeAckFrame{
		LastRecvSeq: sess.LastRecvSeq(),
		LastSentSeq: sess.LastSentSeq(),
	}

	m.logf("[SessionManager] Session resumed: %s (was %s) (lastRecv=%d, lastSent=%d)",
		sess, oldAddr, ack.LastRecvSeq, ack.LastSentSeq)

	// Release the lock before cancelling the old loop (which may block)
	m.mu.Unlock()

	// Cancel the old runSessionLoop and wait for it to exit.
	// This prevents race conditions where the old sshdToStream goroutine
	// competes with the new one to read from sshd and allocate sequence numbers.
	m.logf("[SessionManager] Cancelling old loop for session %s...", sess.ID)
	sess.CancelLoop()
	m.logf("[SessionManager] Old loop cancelled for session %s", sess.ID)

	return sess, ack, nil
}

// GetSession retrieves a session by ID.
func (m *SessionManager) GetSession(id SessionID) (*ServerSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, exists := m.sessions[id]
	return sess, exists
}

// RemoveSession removes and closes a session.
func (m *SessionManager) RemoveSession(id SessionID, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, exists := m.sessions[id]
	if !exists {
		return
	}

	// Send CloseFrame BEFORE cancelling context so the stream is still usable
	sess.CloseStream(reason)
	sess.cancel()
	sess.sshdConn.Close()
	sess.Close(reason)
	delete(m.sessions, id)

	m.logf("[SessionManager] Session removed: %s (reason: %s)", sess, reason)
}

// CleanupExpired removes sessions that have been inactive for too long.
func (m *SessionManager) CleanupExpired() int {
	return m.cleanupInactiveSessions(m.sessionTimeout, "expired", m.logf)
}

// cleanupInactiveSessions is the internal implementation for cleaning up sessions.
// It terminates sessions that have been inactive for longer than the threshold.
func (m *SessionManager) cleanupInactiveSessions(threshold time.Duration, reason string, logf func(string, ...interface{})) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0

	for id, sess := range m.sessions {
		sess.mu.Lock()
		idle := now.Sub(sess.lastActivity)
		sess.mu.Unlock()

		if idle > threshold {
			logf("[SessionManager] Session %s: idle=%v, reason=%s", sess, idle.Round(time.Second), reason)
			// Send CloseFrame BEFORE cancelling context so the stream is still usable
			sess.CloseStream(reason)
			sess.cancel()
			if sess.sshdConn != nil {
				sess.sshdConn.Close()
			}
			sess.Close(reason)
			delete(m.sessions, id)
			removed++
		}
	}

	return removed
}

// startCleanupLoop periodically cleans up expired sessions and handles signals.
// SIGUSR1: dump all sessions to stderr
// SIGUSR2: terminate all sessions inactive for more than 1 minute
func (m *SessionManager) startCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(m.sessionTimeout / 2)
	defer ticker.Stop()

	// Set up signal handlers
	sigUSR1 := make(chan os.Signal, 1)
	sigUSR2 := make(chan os.Signal, 1)
	signal.Notify(sigUSR1, syscall.SIGUSR1)
	signal.Notify(sigUSR2, syscall.SIGUSR2)
	defer signal.Stop(sigUSR1)
	defer signal.Stop(sigUSR2)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if expired := m.CleanupExpired(); expired > 0 {
				m.logf("[SessionManager] Cleaned up %d expired sessions", expired)
			}
		case <-sigUSR1:
			m.dumpSessions()
		case <-sigUSR2:
			m.terminateInactiveSessions(1 * time.Minute)
		}
	}
}

// dumpSessions prints information about all active sessions.
func (m *SessionManager) dumpSessions() {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.logf("=== Session Dump (%d sessions) ===", len(m.sessions))
	for _, sess := range m.sessions {
		sess.mu.Lock()
		idle := time.Since(sess.lastActivity)
		sendBufSize := sess.sendBuffer.Size()
		sendBufFrames := sess.sendBuffer.Len()
		sendBufMinSeq := sess.sendBuffer.MinSeq()
		sendBufMaxSeq := sess.sendBuffer.MaxSeq()
		nextSendSeq := sess.nextSendSeq
		lastRecvSeq := sess.lastRecvSeq
		clientPID := sess.clientPID
		grandparentProcess := sess.grandparentProcess
		var connStats quic.ConnectionStats
		if quicConn := sess.quicConn; quicConn != nil {
			connStats = quicConn.ConnectionStats()
		}
		sess.mu.Unlock()

		stats := sess.ackTracker.Stats()

		m.logf("  Session %s: pid=%d (from=%q) idle=%v sendBuf=%s/%d frames (seq %d-%d) nextSendSeq=%d lastRecvSeq=%d",
			sess, clientPID, grandparentProcess, idle.Round(time.Second),
			fmtBytes(sendBufSize), sendBufFrames, sendBufMinSeq, sendBufMaxSeq,
			nextSendSeq, lastRecvSeq)
		m.logf("    ACKs: pending=%d, acked=%d, highest=%d",
			stats.PendingWrites, stats.AckedPackets, stats.HighestAcked)
		m.logf("    ACK Tracking: lastWrite=%s, lastAck=%s, lastLost=%s (lost=%dpkts)",
			timeAgo(stats.LastWriteTime, now), timeAgo(stats.LastAckTime, now), timeAgo(stats.LastLostTime, now), stats.LostCount)
		m.logf("    QUIC Stats: RTT=%v (min=%v, σ=%v), sent=%s/%dpkts, recv=%s/%dpkts, lost=%s/%dpkts",
			connStats.SmoothedRTT.Round(time.Millisecond),
			connStats.MinRTT.Round(time.Millisecond),
			connStats.MeanDeviation.Round(time.Millisecond),
			fmtBytes(connStats.BytesSent), connStats.PacketsSent,
			fmtBytes(connStats.BytesReceived), connStats.PacketsReceived,
			fmtBytes(connStats.BytesLost), connStats.PacketsLost)
	}
	m.logf("=== End Session Dump ===")
}

// terminateInactiveSessions terminates all sessions that have been inactive
// for longer than the given threshold. This is triggered by SIGUSR2.
func (m *SessionManager) terminateInactiveSessions(threshold time.Duration) {
	terminated := m.cleanupInactiveSessions(threshold, "manual termination", m.logf)
	m.logf("[SessionManager] Terminated %d inactive sessions (threshold: %v)", terminated, threshold)
}

// Count returns the number of active sessions.
func (m *SessionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// UpdateActivity updates the last activity time for a session.
func (m *SessionManager) UpdateActivity(id SessionID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess, exists := m.sessions[id]; exists {
		sess.lastActivity = time.Now()
	}
}

// SSHDReader returns a reader for the sshd connection.
func (ss *ServerSession) SSHDReader() io.Reader {
	return ss.sshdConn
}

// SSHDWriter returns a writer for the sshd connection.
func (ss *ServerSession) SSHDWriter() io.Writer {
	return ss.sshdConn
}

// SetQUICConn installs the ACK hook on the QUIC connection.
// This should be called when a new stream is established for this session.
func (ss *ServerSession) SetQUICConn(conn *quic.Conn) {
	ss.mu.Lock()
	ss.quicConn = conn
	// Clear old tracking state from previous connection
	ss.ackTracker.Clear()
	// Install ACK hook
	conn.SetAckHook(ss.ackTracker)
	ss.mu.Unlock()
	ss.logf("[ServerSession %s] ACK hook installed on QUIC connection", ss)
}

// RecordWrite records a frame write for QUIC ACK tracking.
// This should be called after writing a frame to the stream.
func (ss *ServerSession) RecordWrite(seq uint64) {
	ss.ackTracker.RecordWrite(seq)
}
