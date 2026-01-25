package main

import (
	"bytes"
	"testing"
)

func TestSessionID(t *testing.T) {
	// Test NewSessionID generates non-zero IDs
	id1, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID failed: %v", err)
	}
	if id1.IsZero() {
		t.Error("NewSessionID returned zero ID")
	}

	// Test that two IDs are different
	id2, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID failed: %v", err)
	}
	if id1 == id2 {
		t.Error("Two NewSessionID calls returned the same ID")
	}

	// Test String()
	str := id1.String()
	if len(str) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("SessionID.String() returned wrong length: got %d, want 32", len(str))
	}

	// Test IsZero
	var zeroID SessionID
	if !zeroID.IsZero() {
		t.Error("Zero SessionID.IsZero() returned false")
	}
}

func TestNewSessionFrame(t *testing.T) {
	id, _ := NewSessionID()
	frame := &NewSessionFrame{SessionID: id}

	// Encode
	var buf bytes.Buffer
	if err := frame.Encode(&buf, nil); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Decode
	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	newSession, ok := decoded.(*NewSessionFrame)
	if !ok {
		t.Fatalf("Expected *NewSessionFrame, got %T", decoded)
	}
	if newSession.SessionID != id {
		t.Errorf("SessionID mismatch: got %v, want %v", newSession.SessionID, id)
	}
}

func TestResumeSessionFrame(t *testing.T) {
	id, _ := NewSessionID()
	frame := &ResumeSessionFrame{
		SessionID:   id,
		LastSentSeq: 12345,
		LastRecvSeq: 67890,
	}

	var buf bytes.Buffer
	if err := frame.Encode(&buf, nil); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	resume, ok := decoded.(*ResumeSessionFrame)
	if !ok {
		t.Fatalf("Expected *ResumeSessionFrame, got %T", decoded)
	}
	if resume.SessionID != id {
		t.Errorf("SessionID mismatch")
	}
	if resume.LastSentSeq != 12345 {
		t.Errorf("LastSentSeq mismatch: got %d, want 12345", resume.LastSentSeq)
	}
	if resume.LastRecvSeq != 67890 {
		t.Errorf("LastRecvSeq mismatch: got %d, want 67890", resume.LastRecvSeq)
	}
}

func TestResumeAckFrame(t *testing.T) {
	frame := &ResumeAckFrame{
		LastRecvSeq: 11111,
		LastSentSeq: 22222,
	}

	var buf bytes.Buffer
	if err := frame.Encode(&buf, nil); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	ack, ok := decoded.(*ResumeAckFrame)
	if !ok {
		t.Fatalf("Expected *ResumeAckFrame, got %T", decoded)
	}
	if ack.LastRecvSeq != 11111 {
		t.Errorf("LastRecvSeq mismatch: got %d, want 11111", ack.LastRecvSeq)
	}
	if ack.LastSentSeq != 22222 {
		t.Errorf("LastSentSeq mismatch: got %d, want 22222", ack.LastSentSeq)
	}
}

func TestDataFrame(t *testing.T) {
	payload := []byte("Hello, World!")
	frame := &DataFrame{
		Seq:     42,
		Payload: payload,
	}

	var buf bytes.Buffer
	encBuf := make([]byte, dataFrameBufferSize)
	if err := frame.Encode(&buf, encBuf); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	data, ok := decoded.(*DataFrame)
	if !ok {
		t.Fatalf("Expected *DataFrame, got %T", decoded)
	}
	if data.Seq != 42 {
		t.Errorf("Seq mismatch: got %d, want 42", data.Seq)
	}
	if !bytes.Equal(data.Payload, payload) {
		t.Errorf("Payload mismatch: got %v, want %v", data.Payload, payload)
	}
}

func TestDataFrameEmpty(t *testing.T) {
	frame := &DataFrame{
		Seq:     0,
		Payload: []byte{},
	}

	var buf bytes.Buffer
	encBuf := make([]byte, dataFrameBufferSize)
	if err := frame.Encode(&buf, encBuf); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	data, ok := decoded.(*DataFrame)
	if !ok {
		t.Fatalf("Expected *DataFrame, got %T", decoded)
	}
	if data.Seq != 0 {
		t.Errorf("Seq mismatch: got %d, want 0", data.Seq)
	}
	if len(data.Payload) != 0 {
		t.Errorf("Payload should be empty, got %d bytes", len(data.Payload))
	}
}

func TestAckFrame(t *testing.T) {
	frame := &AckFrame{
		Seq: 99999,
	}

	var buf bytes.Buffer
	if err := frame.Encode(&buf, nil); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	ack, ok := decoded.(*AckFrame)
	if !ok {
		t.Fatalf("Expected *AckFrame, got %T", decoded)
	}
	if ack.Seq != 99999 {
		t.Errorf("Seq mismatch: got %d, want 99999", ack.Seq)
	}
}

func TestCloseFrame(t *testing.T) {
	frame := &CloseFrame{
		Reason: "session timeout",
	}

	var buf bytes.Buffer
	if err := frame.Encode(&buf, nil); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	closeFrame, ok := decoded.(*CloseFrame)
	if !ok {
		t.Fatalf("Expected *CloseFrame, got %T", decoded)
	}
	if closeFrame.Reason != "session timeout" {
		t.Errorf("Reason mismatch: got %q, want %q", closeFrame.Reason, "session timeout")
	}
}

func TestCloseFrameEmpty(t *testing.T) {
	frame := &CloseFrame{
		Reason: "",
	}

	var buf bytes.Buffer
	if err := frame.Encode(&buf, nil); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	closeFrame, ok := decoded.(*CloseFrame)
	if !ok {
		t.Fatalf("Expected *CloseFrame, got %T", decoded)
	}
	if closeFrame.Reason != "" {
		t.Errorf("Reason should be empty, got %q", closeFrame.Reason)
	}
}

func TestDataFrameTooLarge(t *testing.T) {
	// Create a payload larger than 65535 bytes
	payload := make([]byte, 65536)
	frame := &DataFrame{
		Seq:     1,
		Payload: payload,
	}

	var buf bytes.Buffer
	encBuf := make([]byte, dataFrameBufferSize)
	err := frame.Encode(&buf, encBuf)
	if err == nil {
		t.Error("Expected error for oversized payload, got nil")
	}
}

func TestCloseFrameReasonTooLong(t *testing.T) {
	// Create a reason longer than 255 bytes
	reason := string(make([]byte, 256))
	frame := &CloseFrame{
		Reason: reason,
	}

	var buf bytes.Buffer
	err := frame.Encode(&buf, nil)
	if err == nil {
		t.Error("Expected error for oversized reason, got nil")
	}
}
