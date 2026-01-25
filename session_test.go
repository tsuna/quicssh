package main

import (
	"testing"
)

func TestSequenceBuffer(t *testing.T) {
	buf := NewSequenceBuffer(1000) // 1KB max

	// Add some frames
	if err := buf.Add(1, []byte("hello")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if err := buf.Add(2, []byte("world")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if buf.Len() != 2 {
		t.Errorf("Expected 2 frames, got %d", buf.Len())
	}
	if buf.Size() != 10 {
		t.Errorf("Expected size 10, got %d", buf.Size())
	}
	if buf.MinSeq() != 1 {
		t.Errorf("Expected minSeq 1, got %d", buf.MinSeq())
	}
	if buf.MaxSeq() != 2 {
		t.Errorf("Expected maxSeq 2, got %d", buf.MaxSeq())
	}

	// ACK first frame
	buf.AckUpTo(1)
	if buf.Len() != 1 {
		t.Errorf("Expected 1 frame after ACK, got %d", buf.Len())
	}
	if buf.Size() != 5 {
		t.Errorf("Expected size 5 after ACK, got %d", buf.Size())
	}

	// Get frames from seq 0 (should return seq 2)
	frames := buf.GetFromSeq(0)
	if len(frames) != 1 {
		t.Fatalf("Expected 1 frame, got %d", len(frames))
	}
	if frames[0].Seq != 2 {
		t.Errorf("Expected seq 2, got %d", frames[0].Seq)
	}
}

func TestSequenceBufferFull(t *testing.T) {
	buf := NewSequenceBuffer(10) // 10 bytes max

	if err := buf.Add(1, []byte("12345")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if err := buf.Add(2, []byte("12345")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// This should fail - buffer is full
	err := buf.Add(3, []byte("x"))
	if err != ErrBufferFull {
		t.Errorf("Expected ErrBufferFull, got %v", err)
	}

	// ACK first frame, then add should work
	buf.AckUpTo(1)
	if err := buf.Add(3, []byte("x")); err != nil {
		t.Errorf("Add after ACK failed: %v", err)
	}
}

func TestSequenceBufferGetFromSeq(t *testing.T) {
	buf := NewSequenceBuffer(1000)

	// Add frames out of order
	buf.Add(3, []byte("three"))
	buf.Add(1, []byte("one"))
	buf.Add(5, []byte("five"))
	buf.Add(2, []byte("two"))

	// Get all frames after seq 1
	frames := buf.GetFromSeq(1)
	if len(frames) != 3 {
		t.Fatalf("Expected 3 frames, got %d", len(frames))
	}

	// Should be sorted
	if frames[0].Seq != 2 || frames[1].Seq != 3 || frames[2].Seq != 5 {
		t.Errorf("Frames not sorted: %v, %v, %v", frames[0].Seq, frames[1].Seq, frames[2].Seq)
	}
}

func TestSession(t *testing.T) {
	sess, err := NewSession(DefaultBufferSize)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if sess.ID.IsZero() {
		t.Error("Session ID should not be zero")
	}

	// Prepare some data
	frame1, err := sess.PrepareData([]byte("hello"))
	if err != nil {
		t.Fatalf("PrepareData failed: %v", err)
	}
	if frame1.Seq != 1 {
		t.Errorf("Expected seq 1, got %d", frame1.Seq)
	}

	frame2, err := sess.PrepareData([]byte("world"))
	if err != nil {
		t.Fatalf("PrepareData failed: %v", err)
	}
	if frame2.Seq != 2 {
		t.Errorf("Expected seq 2, got %d", frame2.Seq)
	}

	// Check state
	if sess.LastSentSeq() != 2 {
		t.Errorf("Expected LastSentSeq 2, got %d", sess.LastSentSeq())
	}

	// Handle ACK
	sess.HandleAck(&AckFrame{Seq: 1})

	// Get unacked frames
	unacked := sess.GetUnackedFrames(0)
	if len(unacked) != 1 {
		t.Fatalf("Expected 1 unacked frame, got %d", len(unacked))
	}
	if unacked[0].Seq != 2 {
		t.Errorf("Expected unacked seq 2, got %d", unacked[0].Seq)
	}
}

func TestSessionHandleData(t *testing.T) {
	sess, _ := NewSession(DefaultBufferSize)

	// Receive data
	if !sess.HandleData(&DataFrame{Seq: 1, Payload: []byte("a")}) {
		t.Error("Expected new data, got duplicate")
	}
	if sess.LastRecvSeq() != 1 {
		t.Errorf("Expected LastRecvSeq 1, got %d", sess.LastRecvSeq())
	}

	// Duplicate should return false
	if sess.HandleData(&DataFrame{Seq: 1, Payload: []byte("a")}) {
		t.Error("Expected duplicate, got new data")
	}

	// New data
	if !sess.HandleData(&DataFrame{Seq: 2, Payload: []byte("b")}) {
		t.Error("Expected new data, got duplicate")
	}
}
