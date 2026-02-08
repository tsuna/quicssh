package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestIsFatalSessionError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		fatal bool
	}{
		{"nil", nil, false},
		{"EOF", io.EOF, false},
		{"context.Canceled", context.Canceled, false},
		{"net.ErrClosed", net.ErrClosed, false},
		{"wrapped net.ErrClosed", fmt.Errorf("failed: %w", net.ErrClosed), false},
		{"StreamError", &quic.StreamError{StreamID: 0, ErrorCode: 0}, false},
		{"wrapped StreamError", fmt.Errorf("read failed: %w", &quic.StreamError{StreamID: 0, ErrorCode: 0}), false},
		{"application error", errors.New("sshd write failed"), true},
		{"sequence gap", fmt.Errorf("sequence gap: %w", ErrSequenceGap), true},
		{"buffer full", ErrBufferFull, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFatalSessionError(tt.err)
			if got != tt.fatal {
				t.Errorf("isFatalSessionError(%v) = %v, want %v", tt.err, got, tt.fatal)
			}
		})
	}
}

func TestSessionManager_EvictOldest(t *testing.T) {
	// Create a local listener to act as sshd
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Max 2 sessions
	sm := NewSessionManager(ctx, listener.Addr().String(), 5*time.Minute, 2, DefaultBufferSize, t.Logf)

	// Create first session
	id1, _ := NewSessionID()
	sess1, err := sm.HandleNewSession(ctx, &NewSessionFrame{SessionID: id1}, "client1")
	if err != nil {
		t.Fatalf("HandleNewSession 1 failed: %v", err)
	}
	_ = sess1

	// Make sess1 the "oldest" by advancing time
	time.Sleep(10 * time.Millisecond)

	// Create second session
	id2, _ := NewSessionID()
	_, err = sm.HandleNewSession(ctx, &NewSessionFrame{SessionID: id2}, "client2")
	if err != nil {
		t.Fatalf("HandleNewSession 2 failed: %v", err)
	}

	if sm.Count() != 2 {
		t.Fatalf("Expected 2 sessions, got %d", sm.Count())
	}

	// Create third session — should evict the oldest (sess1)
	id3, _ := NewSessionID()
	_, err = sm.HandleNewSession(ctx, &NewSessionFrame{SessionID: id3}, "client3")
	if err != nil {
		t.Fatalf("HandleNewSession 3 failed: %v", err)
	}

	// Should still have 2 sessions (oldest evicted)
	if sm.Count() != 2 {
		t.Errorf("Expected 2 sessions after eviction, got %d", sm.Count())
	}

	// sess1 should be gone
	if _, exists := sm.GetSession(id1); exists {
		t.Error("Session 1 should have been evicted")
	}

	// sess2 and sess3 should still exist
	if _, exists := sm.GetSession(id2); !exists {
		t.Error("Session 2 should still exist")
	}
	if _, exists := sm.GetSession(id3); !exists {
		t.Error("Session 3 should still exist")
	}
}

func TestPrepareData_BufferFull(t *testing.T) {
	// Create a session with a tiny buffer (100 bytes)
	sess := NewSessionWithID(SessionID{1}, 100)

	// Fill the buffer
	_, err := sess.PrepareData(make([]byte, 50))
	if err != nil {
		t.Fatalf("PrepareData 1 failed: %v", err)
	}
	_, err = sess.PrepareData(make([]byte, 50))
	if err != nil {
		t.Fatalf("PrepareData 2 failed: %v", err)
	}

	// Next should fail with ErrBufferFull
	seqBefore := sess.LastSentSeq()
	_, err = sess.PrepareData(make([]byte, 10))
	if err != ErrBufferFull {
		t.Fatalf("Expected ErrBufferFull, got %v", err)
	}

	// Sequence number should have been rolled back
	seqAfter := sess.LastSentSeq()
	if seqAfter != seqBefore {
		t.Errorf("Sequence number should be rolled back: before=%d, after=%d", seqBefore, seqAfter)
	}

	// After ACKing some data, PrepareData should work again
	sess.HandleAck(&AckFrame{Seq: 1})
	frame, err := sess.PrepareData(make([]byte, 10))
	if err != nil {
		t.Fatalf("PrepareData after ACK failed: %v", err)
	}
	// Sequence should continue from where it was
	if frame.Seq != seqBefore+1 {
		t.Errorf("Expected seq %d, got %d", seqBefore+1, frame.Seq)
	}
}

func TestPrepareData_ClosedSession(t *testing.T) {
	sess := NewSessionWithID(SessionID{1}, DefaultBufferSize)
	sess.Close("test")

	_, err := sess.PrepareData([]byte("data"))
	if err == nil {
		t.Fatal("Expected error on closed session")
	}
	if err.Error() != "session is closed" {
		t.Errorf("Expected 'session is closed' error, got: %v", err)
	}
}

func TestHandleData_DuplicateWithLogging(t *testing.T) {
	sess := NewSessionWithID(SessionID{1}, DefaultBufferSize)

	// Receive seq 1
	isNew, err := sess.HandleData(&DataFrame{Seq: 1, Payload: []byte("a")}, t.Logf)
	if err != nil || !isNew {
		t.Fatalf("Expected new data: isNew=%v, err=%v", isNew, err)
	}

	// Duplicate seq 1 with logging
	isNew, err = sess.HandleData(&DataFrame{Seq: 1, Payload: []byte("a")}, t.Logf)
	if err != nil {
		t.Fatalf("Unexpected error on duplicate: %v", err)
	}
	if isNew {
		t.Error("Expected duplicate, got new")
	}

	// LastRecvSeq should still be 1
	if sess.LastRecvSeq() != 1 {
		t.Errorf("Expected LastRecvSeq 1, got %d", sess.LastRecvSeq())
	}
}

func TestHandleData_GapWithLogging(t *testing.T) {
	sess := NewSessionWithID(SessionID{1}, DefaultBufferSize)

	// Receive seq 1
	sess.HandleData(&DataFrame{Seq: 1, Payload: []byte("a")}, t.Logf)

	// Skip to seq 5 — gap of 3 frames
	isNew, err := sess.HandleData(&DataFrame{Seq: 5, Payload: []byte("e")}, t.Logf)
	if !errors.Is(err, ErrSequenceGap) {
		t.Fatalf("Expected ErrSequenceGap, got %v", err)
	}
	if isNew {
		t.Error("Expected isNew=false on gap")
	}

	// LastRecvSeq should NOT advance past the gap
	if sess.LastRecvSeq() != 1 {
		t.Errorf("Expected LastRecvSeq 1, got %d", sess.LastRecvSeq())
	}
}

func TestHandleData_SequentialDelivery(t *testing.T) {
	sess := NewSessionWithID(SessionID{1}, DefaultBufferSize)

	// Deliver frames 1 through 100 in order
	for i := uint64(1); i <= 100; i++ {
		isNew, err := sess.HandleData(&DataFrame{Seq: i, Payload: []byte{byte(i)}})
		if err != nil {
			t.Fatalf("HandleData seq=%d failed: %v", i, err)
		}
		if !isNew {
			t.Fatalf("HandleData seq=%d should be new", i)
		}
	}
	if sess.LastRecvSeq() != 100 {
		t.Errorf("Expected LastRecvSeq 100, got %d", sess.LastRecvSeq())
	}
}

func TestSendAck_Batching(t *testing.T) {
	cs, err := NewClientSession(DefaultBufferSize, noopLogf)
	if err != nil {
		t.Fatalf("NewClientSession failed: %v", err)
	}
	stream := newMockStream()
	cs.Connect(stream)
	stream.writeBuf.Reset()

	// First frame + SendAck triggers immediately (lastAckTime is zero)
	cs.HandleData(&DataFrame{Seq: 1, Payload: []byte{1}})
	cs.SendAck()
	if stream.writeBuf.Len() == 0 {
		t.Fatal("Expected immediate ACK on first call (lastAckTime is zero)")
	}
	frame, _ := ReadFrame(stream.writeBuf)
	if ack, ok := frame.(*AckFrame); !ok || ack.Seq != 1 {
		t.Fatalf("Expected AckFrame seq=1, got %T %v", frame, frame)
	}
	stream.writeBuf.Reset()

	// Now send ackBatchFrames-1 more frames — should NOT trigger ACK
	for i := uint64(2); i <= ackBatchFrames; i++ {
		cs.HandleData(&DataFrame{Seq: i, Payload: []byte{byte(i)}})
		cs.SendAck()
	}
	if stream.writeBuf.Len() > 0 {
		t.Errorf("Expected no ACK before threshold, but got %d bytes", stream.writeBuf.Len())
	}

	// One more frame should hit the frame threshold and trigger the ACK
	cs.HandleData(&DataFrame{Seq: ackBatchFrames + 1, Payload: []byte{0}})
	cs.SendAck()

	if stream.writeBuf.Len() == 0 {
		t.Error("Expected ACK to be sent after reaching frame threshold")
	}

	frame, err = ReadFrame(stream.writeBuf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	ack, ok := frame.(*AckFrame)
	if !ok {
		t.Fatalf("Expected AckFrame, got %T", frame)
	}
	if ack.Seq != ackBatchFrames+1 {
		t.Errorf("Expected ACK seq %d, got %d", ackBatchFrames+1, ack.Seq)
	}
}

func TestSendAck_TimeThreshold(t *testing.T) {
	cs, err := NewClientSession(DefaultBufferSize, noopLogf)
	if err != nil {
		t.Fatalf("NewClientSession failed: %v", err)
	}
	stream := newMockStream()
	cs.Connect(stream)
	stream.writeBuf.Reset()

	// Receive one frame
	cs.HandleData(&DataFrame{Seq: 1, Payload: []byte("a")})
	cs.SendAck() // First call triggers immediately (lastAckTime is zero)

	// Read the ACK
	frame, _ := ReadFrame(stream.writeBuf)
	if _, ok := frame.(*AckFrame); !ok {
		t.Fatalf("Expected initial AckFrame, got %T", frame)
	}
	stream.writeBuf.Reset()

	// Receive another frame — should NOT trigger ACK (under both thresholds)
	cs.HandleData(&DataFrame{Seq: 2, Payload: []byte("b")})
	cs.SendAck()
	if stream.writeBuf.Len() > 0 {
		t.Error("Expected no ACK before time threshold")
	}

	// Wait for the time threshold to pass
	time.Sleep(ackBatchTimeout + 10*time.Millisecond)

	// Now SendAck should trigger
	cs.HandleData(&DataFrame{Seq: 3, Payload: []byte("c")})
	cs.SendAck()
	if stream.writeBuf.Len() == 0 {
		t.Error("Expected ACK after time threshold")
	}
}

func TestSendAck_NotConnected(t *testing.T) {
	cs, _ := NewClientSession(DefaultBufferSize, noopLogf)
	// Not connected — SendAck should be a no-op
	if err := cs.SendAck(); err != nil {
		t.Errorf("SendAck on disconnected session should not error: %v", err)
	}
}

func TestSendAck_NoDataReceived(t *testing.T) {
	cs, _ := NewClientSession(DefaultBufferSize, noopLogf)
	stream := newMockStream()
	cs.Connect(stream)
	stream.writeBuf.Reset()

	// Connected but no data received — SendAck should be a no-op
	if err := cs.SendAck(); err != nil {
		t.Errorf("SendAck with no data should not error: %v", err)
	}
	if stream.writeBuf.Len() > 0 {
		t.Error("Expected no ACK when no data received")
	}
}

func TestSessionManager_DuplicateSession(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := NewSessionManager(ctx, listener.Addr().String(), 5*time.Minute, 0, DefaultBufferSize, noopLogf)

	id, _ := NewSessionID()
	_, err = sm.HandleNewSession(ctx, &NewSessionFrame{SessionID: id}, "client1")
	if err != nil {
		t.Fatalf("First HandleNewSession failed: %v", err)
	}

	// Same session ID should fail
	_, err = sm.HandleNewSession(ctx, &NewSessionFrame{SessionID: id}, "client2")
	if err == nil {
		t.Fatal("Expected error for duplicate session ID")
	}
}

func TestSequenceBuffer_AckUpTo_Empty(t *testing.T) {
	buf := NewSequenceBuffer(1000)

	// ACK on empty buffer should be safe
	removed, _, _ := buf.AckUpTo(5)
	if removed != 0 {
		t.Errorf("Expected 0 removed from empty buffer, got %d", removed)
	}
}

func TestSequenceBuffer_IsFull(t *testing.T) {
	buf := NewSequenceBuffer(100)

	buf.Add(1, make([]byte, 90))

	// 10 bytes left — payload of 10 should NOT be full
	if buf.IsFull(10) {
		t.Error("Buffer should not be full with 10 bytes left for 10 byte payload")
	}

	// 10 bytes left — payload of 11 should be full
	if !buf.IsFull(11) {
		t.Error("Buffer should be full with 10 bytes left for 11 byte payload")
	}
}

func TestSession_ReconnectStats(t *testing.T) {
	sess, _ := NewSession(DefaultBufferSize)

	count, lastTime := sess.ReconnectStats()
	if count != 0 || !lastTime.IsZero() {
		t.Errorf("Expected 0 reconnects and zero time, got %d, %v", count, lastTime)
	}

	sess.RecordReconnect()
	count, lastTime = sess.ReconnectStats()
	if count != 1 {
		t.Errorf("Expected 1 reconnect, got %d", count)
	}
	if lastTime.IsZero() {
		t.Error("Expected non-zero last reconnect time")
	}
}
