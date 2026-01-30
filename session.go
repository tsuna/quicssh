package main

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Session represents the state of a session that can survive QUIC connection failures.
// It tracks sequence numbers and maintains buffers for unacknowledged data.
type Session struct {
	ID SessionID

	mu sync.Mutex

	// Send-side state
	nextSendSeq  uint64          // Next sequence number to use when sending
	sendBuffer   *SequenceBuffer // Buffer of sent but unacknowledged data
	encodeBuffer []byte          // Reusable buffer for encoding DataFrames

	// Receive-side state
	lastRecvSeq uint64 // Last sequence number received (for ACKs and resume)

	// Session state
	closed      bool
	closeReason string
}

// SequenceBuffer holds data frames indexed by sequence number.
// Used to buffer sent data until acknowledged, enabling replay on reconnect.
type SequenceBuffer struct {
	mu      sync.Mutex
	frames  map[uint64][]byte // seq -> payload
	minSeq  uint64            // Minimum sequence in buffer (for cleanup)
	maxSeq  uint64            // Maximum sequence in buffer
	maxSize int               // Maximum total bytes to buffer
	size    int               // Current total bytes in buffer
}

// NewSequenceBuffer creates a new sequence buffer with the given max size.
func NewSequenceBuffer(maxSize int) *SequenceBuffer {
	return &SequenceBuffer{
		frames:  make(map[uint64][]byte),
		maxSize: maxSize,
	}
}

// Add adds a frame to the buffer. Returns error if buffer is full.
func (b *SequenceBuffer) Add(seq uint64, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size+len(payload) > b.maxSize {
		return ErrBufferFull
	}

	// Make a copy of the payload
	data := make([]byte, len(payload))
	copy(data, payload)

	b.frames[seq] = data
	b.size += len(payload)

	if len(b.frames) == 1 {
		b.minSeq = seq
		b.maxSeq = seq
	} else {
		if seq < b.minSeq {
			b.minSeq = seq
		}
		if seq > b.maxSeq {
			b.maxSeq = seq
		}
	}

	return nil
}

// AckUpTo removes all frames with sequence <= seq from the buffer.
// Returns the number of frames removed and the sequence range that was removed.
func (b *SequenceBuffer) AckUpTo(seq uint64) (removedCount int, removedMinSeq, removedMaxSeq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	removedMinSeq = ^uint64(0) // Max uint64
	removedMaxSeq = 0

	for s, payload := range b.frames {
		if s <= seq {
			b.size -= len(payload)
			delete(b.frames, s)
			removedCount++
			if s < removedMinSeq {
				removedMinSeq = s
			}
			if s > removedMaxSeq {
				removedMaxSeq = s
			}
		}
	}

	if removedCount == 0 {
		removedMinSeq = 0
	}

	// Update minSeq
	if len(b.frames) == 0 {
		b.minSeq = seq + 1
	} else {
		newMin := b.maxSeq
		for s := range b.frames {
			if s < newMin {
				newMin = s
			}
		}
		b.minSeq = newMin
	}

	return removedCount, removedMinSeq, removedMaxSeq
}

// GetFromSeq returns all frames with sequence > seq, in order.
func (b *SequenceBuffer) GetFromSeq(seq uint64) []DataFrame {
	b.mu.Lock()
	defer b.mu.Unlock()

	var frames []DataFrame
	for s, payload := range b.frames {
		if s > seq {
			frames = append(frames, DataFrame{Seq: s, Payload: payload})
		}
	}

	// Sort by sequence number
	for i := 0; i < len(frames); i++ {
		for j := i + 1; j < len(frames); j++ {
			if frames[i].Seq > frames[j].Seq {
				frames[i], frames[j] = frames[j], frames[i]
			}
		}
	}

	return frames
}

// MinSeq returns the minimum sequence number in the buffer.
func (b *SequenceBuffer) MinSeq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.minSeq
}

// MaxSeq returns the maximum sequence number in the buffer.
func (b *SequenceBuffer) MaxSeq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxSeq
}

// Size returns the current size of the buffer in bytes.
func (b *SequenceBuffer) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size
}

// Len returns the number of frames in the buffer.
func (b *SequenceBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.frames)
}

// ErrBufferFull is returned when the send buffer is full.
var ErrBufferFull = errors.New("send buffer full")

// DefaultBufferSize is the default maximum size for the send buffer (16MB).
// This matches MaxStreamReceiveWindow in the QUIC config to avoid backpressure
// before the QUIC flow control window is filled.
const DefaultBufferSize = 16 * 1024 * 1024

// IsFull returns true if adding the given payload would exceed the buffer limit.
func (b *SequenceBuffer) IsFull(payloadSize int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size+payloadSize > b.maxSize
}

// NewSession creates a new session with a random SessionID.
func NewSession(bufferSize int) (*Session, error) {
	id, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	return &Session{
		ID:           id,
		nextSendSeq:  1, // Start at 1, 0 means "no data sent yet"
		sendBuffer:   NewSequenceBuffer(bufferSize),
		encodeBuffer: make([]byte, dataFrameBufferSize),
		lastRecvSeq:  0, // 0 means "no data received yet"
	}, nil
}

// NewSessionWithID creates a session with a specific SessionID (used by server).
func NewSessionWithID(id SessionID, bufferSize int) *Session {
	return &Session{
		ID:           id,
		nextSendSeq:  1,
		sendBuffer:   NewSequenceBuffer(bufferSize),
		encodeBuffer: make([]byte, dataFrameBufferSize),
		lastRecvSeq:  0,
	}
}

// EncodeBuffer returns the session's reusable buffer for encoding DataFrames.
// This buffer is owned by the session and should only be used for serial writes.
func (s *Session) EncodeBuffer() []byte {
	return s.encodeBuffer
}

// SendBufferIsFull returns true if the send buffer cannot accept a payload of the given size.
// This is used for backpressure - callers should stop reading input when this returns true.
func (s *Session) SendBufferIsFull(payloadSize int) bool {
	return s.sendBuffer.IsFull(payloadSize)
}

// SendBufferSize returns the current size of the send buffer in bytes.
func (s *Session) SendBufferSize() int {
	return s.sendBuffer.Size()
}

// PrepareData creates a DataFrame for the given payload and buffers it.
// Returns the DataFrame ready to be sent, or error if buffer is full.
func (s *Session) PrepareData(payload []byte) (*DataFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("session is closed")
	}

	seq := s.nextSendSeq
	s.nextSendSeq++

	// Buffer the data for potential replay
	if err := s.sendBuffer.Add(seq, payload); err != nil {
		s.nextSendSeq-- // Rollback
		return nil, err
	}

	return &DataFrame{
		Seq:     seq,
		Payload: payload,
	}, nil
}

// HandleAck processes an ACK frame, clearing acknowledged data from the buffer.
// Returns the number of frames removed and the sequence range that was removed.
func (s *Session) HandleAck(ack *AckFrame) (removedCount int, removedMinSeq, removedMaxSeq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.sendBuffer.AckUpTo(ack.Seq)
}

// HandleData processes a received DATA frame.
// Returns true if this is new data (not a duplicate), false if duplicate.
func (s *Session) HandleData(data *DataFrame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate
	if data.Seq <= s.lastRecvSeq {
		return false // Duplicate
	}

	// Note: This simple implementation assumes in-order delivery.
	// For out-of-order, we'd need a receive buffer too.
	s.lastRecvSeq = data.Seq
	return true
}

// LastRecvSeq returns the last received sequence number.
func (s *Session) LastRecvSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRecvSeq
}

// LastSentSeq returns the last sent sequence number (nextSendSeq - 1).
func (s *Session) LastSentSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextSendSeq == 0 {
		return 0
	}
	return s.nextSendSeq - 1
}

// GetUnackedFrames returns all unacknowledged frames starting from afterSeq.
func (s *Session) GetUnackedFrames(afterSeq uint64) []DataFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendBuffer.GetFromSeq(afterSeq)
}

// Close marks the session as closed.
func (s *Session) Close(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.closeReason = reason
}

// IsClosed returns true if the session is closed.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// ResumeState returns the state needed for a RESUME_SESSION frame.
func (s *Session) ResumeState() (lastSentSeq, lastRecvSeq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextSendSeq - 1, s.lastRecvSeq
}

// fmtBytes formats bytes in human-readable form (e.g., "42b", "1.5KB", "2.3MB").
func fmtBytes[T ~int | ~uint64](b T) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%db", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.1fGB", float64(b)/(1024*1024*1024))
	}
}

// timeAgo formats a time as "Xms ago", "Xs ago", etc. Returns "never" for zero time.
func timeAgo(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmt.Sprintf("%v ago", now.Sub(t).Round(time.Millisecond))
}
