package main

import (
	"sync"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestAckTracker_RecordWrite(t *testing.T) {
	tracker := NewAckTracker(nil, nil)

	// Record some writes
	tracker.RecordWrite(1)
	tracker.RecordWrite(2)
	tracker.RecordWrite(3)

	stats := tracker.Stats()
	if stats.PendingWrites != 3 {
		t.Errorf("Expected 3 pending writes, got %d", stats.PendingWrites)
	}
}

func TestAckTracker_OnPacketsAcked_ClearsAllWrites(t *testing.T) {
	var clearedSeq uint64
	var callCount int

	tracker := NewAckTracker(func(upToSeq uint64) {
		clearedSeq = upToSeq
		callCount++
	}, nil)

	// Record writes
	tracker.RecordWrite(1)
	tracker.RecordWrite(2)
	tracker.RecordWrite(3)

	// First ACK clears all pending writes immediately
	tracker.OnPacketsAcked([]quic.PacketNumber{1})
	if callCount != 1 {
		t.Errorf("Expected 1 callback after ACK, got %d calls", callCount)
	}
	if clearedSeq != 3 {
		t.Errorf("Expected cleared seq 3 (highest), got %d", clearedSeq)
	}

	// Verify all writes are cleared
	stats := tracker.Stats()
	if stats.PendingWrites != 0 {
		t.Errorf("Expected 0 pending writes, got %d", stats.PendingWrites)
	}

	// Second ACK with no pending writes - no callback
	tracker.OnPacketsAcked([]quic.PacketNumber{2})
	if callCount != 1 {
		t.Errorf("Expected still 1 callback (no new writes), got %d calls", callCount)
	}
}

func TestAckTracker_OnPacketsAcked_NoPendingWrites(t *testing.T) {
	var callCount int

	tracker := NewAckTracker(func(upToSeq uint64) {
		callCount++
	}, nil)

	// ACK without any pending writes - no callback
	tracker.OnPacketsAcked([]quic.PacketNumber{1, 2, 3})
	if callCount != 0 {
		t.Errorf("Expected no callback with no pending writes, got %d calls", callCount)
	}
}

func TestAckTracker_OnActivity(t *testing.T) {
	var activityCount int

	tracker := NewAckTracker(nil, func() {
		activityCount++
	})

	// ACK should trigger onActivity even without pending writes
	tracker.OnPacketsAcked([]quic.PacketNumber{1})
	if activityCount != 1 {
		t.Errorf("Expected 1 activity callback, got %d", activityCount)
	}

	// Multiple ACKs should trigger multiple activity callbacks
	tracker.OnPacketsAcked([]quic.PacketNumber{2, 3, 4})
	if activityCount != 2 {
		t.Errorf("Expected 2 activity callbacks, got %d", activityCount)
	}
}

func TestAckTracker_Clear(t *testing.T) {
	tracker := NewAckTracker(nil, nil)

	// Record writes and ACKs
	tracker.RecordWrite(1)
	tracker.RecordWrite(2)
	tracker.OnPacketsAcked([]quic.PacketNumber{1, 2, 3})

	// Clear
	tracker.Clear()

	stats := tracker.Stats()
	if stats.PendingWrites != 0 {
		t.Errorf("Expected 0 pending writes after clear, got %d", stats.PendingWrites)
	}
	if stats.AckedPackets != 0 {
		t.Errorf("Expected 0 acked packets after clear, got %d", stats.AckedPackets)
	}
	if stats.HighestAcked != 0 {
		t.Errorf("Expected 0 highest acked after clear, got %d", stats.HighestAcked)
	}
}

func TestAckTracker_HighestSeqCleared(t *testing.T) {
	// Test that when multiple sequences are clearable, we report the highest
	var clearedSeq uint64

	tracker := NewAckTracker(func(upToSeq uint64) {
		clearedSeq = upToSeq
	}, nil)

	// Record writes out of order (seq 5, 3, 1)
	tracker.RecordWrite(5)
	tracker.RecordWrite(3)
	tracker.RecordWrite(1)

	// ACK enough packets to clear all
	tracker.OnPacketsAcked([]quic.PacketNumber{1, 2, 3, 4, 5, 6, 7})

	// Should report highest clearable seq
	if clearedSeq != 5 {
		t.Errorf("Expected cleared seq 5 (highest), got %d", clearedSeq)
	}
}

func TestAckTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewAckTracker(func(upToSeq uint64) {
		// Just a no-op callback
	}, nil)

	var wg sync.WaitGroup
	const numGoroutines = 10
	const numOps = 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				tracker.RecordWrite(uint64(base*numOps + j))
			}
		}(i)
	}

	// Concurrent ACKs
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				tracker.OnPacketsAcked([]quic.PacketNumber{quic.PacketNumber(base*numOps + j)})
			}
		}(i)
	}

	wg.Wait()
	// If we get here without deadlock or panic, the test passes
}
