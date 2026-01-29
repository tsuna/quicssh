package main

import (
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// AckTracker tracks DataFrame sequence numbers that have been written but not yet acknowledged.
// It implements quic.AckHookCallback to receive notifications when packets are acknowledged.
//
// Since QUIC guarantees reliable, ordered delivery within a stream, when we receive an ACK
// for any packet, all data written before that packet was sent is guaranteed to have been
// received by the peer. We use this to clear acknowledged DataFrames from the send buffer.
type AckTracker struct {
	mu sync.Mutex

	// Callback to clear acknowledged data from the session's send buffer
	onAck func(upToSeq uint64)

	// Callback for any QUIC activity (used to update lastActivity for keep-alives)
	onActivity func()

	// Pending writes: sequence numbers of DataFrames not yet acknowledged
	pendingSeqs []uint64

	// ACK tracking (for stats/debugging)
	highestAckedPacket quic.PacketNumber
	ackedPacketCount   uint64

	// Timestamps for debugging
	lastWriteTime time.Time
	lastAckTime   time.Time
	lastLostTime  time.Time
	lostCount     uint64
}

// NewAckTracker creates a new AckTracker.
// onAck is called with the highest sequence number that can be cleared from the buffer.
// onActivity is called whenever any QUIC packet is acknowledged (including keep-alives).
func NewAckTracker(onAck func(upToSeq uint64), onActivity func()) *AckTracker {
	return &AckTracker{
		onAck:      onAck,
		onActivity: onActivity,
	}
}

// RecordWrite records that a DataFrame with the given sequence number was written.
// This should be called immediately after writing the frame to the stream.
func (t *AckTracker) RecordWrite(seq uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pendingSeqs = append(t.pendingSeqs, seq)
	t.lastWriteTime = time.Now()
}

// OnPacketsAcked is called when QUIC packets are acknowledged.
// This implements the quic.AckHookCallback interface.
//
// Since QUIC guarantees ordered delivery within a stream, when any packet is ACKed,
// all data written before that packet was sent has been received. We clear all
// pending writes and notify the session to clear its send buffer.
func (t *AckTracker) OnPacketsAcked(packets []quic.PacketNumber) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Update stats and timestamp
	t.lastAckTime = time.Now()
	for _, pn := range packets {
		if pn > t.highestAckedPacket {
			t.highestAckedPacket = pn
		}
		t.ackedPacketCount++
	}

	// Notify that there's QUIC activity (for keep-alive tracking)
	if t.onActivity != nil {
		t.onActivity()
	}

	// Find the highest pending sequence number and clear all
	if len(t.pendingSeqs) == 0 {
		return
	}

	var highestSeq uint64
	for _, seq := range t.pendingSeqs {
		if seq > highestSeq {
			highestSeq = seq
		}
	}

	// Clear all pending writes
	t.pendingSeqs = t.pendingSeqs[:0]

	// Notify the session to clear acknowledged data
	if t.onAck != nil {
		t.onAck(highestSeq)
	}
}

// OnPacketLost is called when a QUIC packet is declared lost.
// This implements the quic.AckHookCallback interface.
// QUIC handles retransmission internally, so we don't need to take action.
func (t *AckTracker) OnPacketLost(pn quic.PacketNumber) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.lastLostTime = time.Now()
	t.lostCount++
}

// Clear removes all tracking state. Called when the connection is reset.
func (t *AckTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pendingSeqs = t.pendingSeqs[:0]
	t.highestAckedPacket = 0
	t.ackedPacketCount = 0
	t.lastWriteTime = time.Time{}
	t.lastAckTime = time.Time{}
	t.lastLostTime = time.Time{}
	t.lostCount = 0
}

// AckTrackerStats holds statistics from the AckTracker for debugging.
type AckTrackerStats struct {
	PendingWrites int
	AckedPackets  uint64
	HighestAcked  quic.PacketNumber
	LastWriteTime time.Time
	LastAckTime   time.Time
	LastLostTime  time.Time
	LostCount     uint64
}

// Stats returns current tracking statistics for debugging.
func (t *AckTracker) Stats() AckTrackerStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return AckTrackerStats{
		PendingWrites: len(t.pendingSeqs),
		AckedPackets:  t.ackedPacketCount,
		HighestAcked:  t.highestAckedPacket,
		LastWriteTime: t.lastWriteTime,
		LastAckTime:   t.lastAckTime,
		LastLostTime:  t.lastLostTime,
		LostCount:     t.lostCount,
	}
}
