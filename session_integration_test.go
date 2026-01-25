package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// mockStream implements io.ReadWriteCloser for testing
type mockStream struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func newMockStream() *mockStream {
	return &mockStream{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (m *mockStream) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuf.Read(p)
}

func (m *mockStream) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.writeBuf.Write(p)
}

func (m *mockStream) Close() error {
	m.closed = true
	return nil
}

// Helper to create a connected pair of mock streams
func newMockStreamPair() (*mockStream, *mockStream) {
	client := newMockStream()
	server := newMockStream()
	// Connect them: client writes go to server reads, and vice versa
	client.readBuf = server.writeBuf
	server.readBuf = client.writeBuf
	return client, server
}

func noopLogf(format string, args ...interface{}) {}

// TestClientSession_Connect tests the NEW_SESSION handshake
func TestClientSession_Connect(t *testing.T) {
	cs, err := NewClientSession(DefaultBufferSize, noopLogf)
	if err != nil {
		t.Fatalf("NewClientSession failed: %v", err)
	}

	stream := newMockStream()

	// Connect should send NEW_SESSION frame
	if err := cs.Connect(stream); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Verify NEW_SESSION was written
	frame, err := ReadFrame(stream.writeBuf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	newSess, ok := frame.(*NewSessionFrame)
	if !ok {
		t.Fatalf("Expected NewSessionFrame, got %T", frame)
	}
	if newSess.SessionID != cs.ID {
		t.Errorf("SessionID mismatch: got %v, want %v", newSess.SessionID, cs.ID)
	}

	// Should be connected
	if !cs.IsConnected() {
		t.Error("Expected IsConnected() to be true")
	}
}

// TestClientSession_SendData tests sending DATA frames
func TestClientSession_SendData(t *testing.T) {
	cs, _ := NewClientSession(DefaultBufferSize, noopLogf)
	stream := newMockStream()
	cs.Connect(stream)

	// Clear the NEW_SESSION frame from buffer
	stream.writeBuf.Reset()

	ctx := context.Background()
	if err := cs.SendData(ctx, []byte("hello")); err != nil {
		t.Fatalf("SendData failed: %v", err)
	}

	// Verify DATA frame was written
	frame, err := ReadFrame(stream.writeBuf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	data, ok := frame.(*DataFrame)
	if !ok {
		t.Fatalf("Expected DataFrame, got %T", frame)
	}
	if data.Seq != 1 {
		t.Errorf("Expected seq 1, got %d", data.Seq)
	}
	if !bytes.Equal(data.Payload, []byte("hello")) {
		t.Errorf("Payload mismatch")
	}

	// Send another
	stream.writeBuf.Reset()
	if err := cs.SendData(ctx, []byte("world")); err != nil {
		t.Fatalf("SendData failed: %v", err)
	}

	frame, _ = ReadFrame(stream.writeBuf)
	data = frame.(*DataFrame)
	if data.Seq != 2 {
		t.Errorf("Expected seq 2, got %d", data.Seq)
	}
}

// TestClientSession_Resume tests the RESUME_SESSION handshake
func TestClientSession_Resume(t *testing.T) {
	cs, _ := NewClientSession(DefaultBufferSize, noopLogf)

	// Simulate previous connection state
	cs.PrepareData([]byte("data1")) // seq 1
	cs.PrepareData([]byte("data2")) // seq 2
	cs.PrepareData([]byte("data3")) // seq 3
	cs.HandleData(&DataFrame{Seq: 1, Payload: []byte("recv1")})
	cs.HandleData(&DataFrame{Seq: 2, Payload: []byte("recv2")})

	// Create new stream for resume
	stream := newMockStream()

	// Prepare RESUME_ACK response (server received seq 1, sent seq 2)
	ack := &ResumeAckFrame{LastRecvSeq: 1, LastSentSeq: 2}
	ack.Encode(stream.readBuf, nil)

	// Resume
	framesToReplay, err := cs.Resume(stream)
	if err != nil {
		t.Fatalf("Resume failed: %v", err)
	}

	// Should have 2 frames to replay (seq 2 and 3)
	if len(framesToReplay) != 2 {
		t.Fatalf("Expected 2 frames to replay, got %d", len(framesToReplay))
	}
	if framesToReplay[0].Seq != 2 || framesToReplay[1].Seq != 3 {
		t.Errorf("Wrong replay frames: %v, %v", framesToReplay[0].Seq, framesToReplay[1].Seq)
	}
}

// TestClientSession_Disconnect tests disconnection
func TestClientSession_Disconnect(t *testing.T) {
	cs, _ := NewClientSession(DefaultBufferSize, noopLogf)
	stream := newMockStream()
	cs.Connect(stream)

	if !cs.IsConnected() {
		t.Error("Should be connected")
	}

	cs.Disconnect()

	if cs.IsConnected() {
		t.Error("Should be disconnected")
	}
}

// TestSessionManager_NewSession tests creating a new session
func TestSessionManager_NewSession(t *testing.T) {
	// Create a local listener to act as sshd
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Echo server
			go io.Copy(conn, conn)
		}
	}()

	ctx := context.Background()
	sm := NewSessionManager(ctx, listener.Addr().String(), 5*time.Minute, 0, DefaultBufferSize, noopLogf)

	sessionID, _ := NewSessionID()

	frame := &NewSessionFrame{SessionID: sessionID}
	sess, err := sm.HandleNewSession(ctx, frame, "127.0.0.1:12345")
	if err != nil {
		t.Fatalf("HandleNewSession failed: %v", err)
	}

	if sess == nil {
		t.Fatal("Session should not be nil")
	}
	if sess.ID != sessionID {
		t.Errorf("Session ID mismatch")
	}

	// Should be able to retrieve it
	retrieved, exists := sm.GetSession(sessionID)
	if !exists || retrieved == nil {
		t.Error("GetSession returned nil")
	}

	// Count should be 1
	if sm.Count() != 1 {
		t.Errorf("Expected count 1, got %d", sm.Count())
	}

	// Remove it
	sm.RemoveSession(sessionID, "test cleanup")
	if sm.Count() != 0 {
		t.Errorf("Expected count 0 after removal, got %d", sm.Count())
	}
}

// TestSessionManager_ResumeSession tests resuming an existing session
func TestSessionManager_ResumeSession(t *testing.T) {
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
			go io.Copy(conn, conn)
		}
	}()

	ctx := context.Background()
	sm := NewSessionManager(ctx, listener.Addr().String(), 5*time.Minute, 0, DefaultBufferSize, noopLogf)

	// Create initial session
	sessionID, _ := NewSessionID()
	newFrame := &NewSessionFrame{SessionID: sessionID}
	sess, _ := sm.HandleNewSession(ctx, newFrame, "127.0.0.1:12345")

	// Simulate some data exchange
	sess.PrepareData([]byte("sent1")) // seq 1
	sess.PrepareData([]byte("sent2")) // seq 2
	sess.HandleData(&DataFrame{Seq: 1, Payload: []byte("recv1")})

	// Resume with client claiming they sent up to seq 2, received up to seq 0
	// Simulate client reconnecting from a different port
	resumeFrame := &ResumeSessionFrame{SessionID: sessionID, LastSentSeq: 2, LastRecvSeq: 0}
	resumedSess, ack, err := sm.HandleResumeSession(resumeFrame, "127.0.0.1:54321")
	if err != nil {
		t.Fatalf("HandleResumeSession failed: %v", err)
	}

	if resumedSess == nil {
		t.Fatal("Resumed session should not be nil")
	}

	// ACK should tell client what server has received (lastRecvSeq from server's perspective)
	// Server received seq 1 from client
	if ack.LastRecvSeq != 1 {
		t.Errorf("Expected LastRecvSeq 1, got %d", ack.LastRecvSeq)
	}

	// ACK should tell client what server has sent (lastSentSeq)
	if ack.LastSentSeq != 2 {
		t.Errorf("Expected LastSentSeq 2, got %d", ack.LastSentSeq)
	}
}

// TestSessionManager_CleanupExpired tests session expiration
func TestSessionManager_CleanupExpired(t *testing.T) {
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

	// Use a very short timeout
	ctx := context.Background()
	sm := NewSessionManager(ctx, listener.Addr().String(), 10*time.Millisecond, 0, DefaultBufferSize, noopLogf)

	sessionID, _ := NewSessionID()
	frame := &NewSessionFrame{SessionID: sessionID}
	sm.HandleNewSession(ctx, frame, "127.0.0.1:12345")

	if sm.Count() != 1 {
		t.Errorf("Expected count 1, got %d", sm.Count())
	}

	// Wait for expiration and automatic cleanup (cleanup loop runs every timeout/2 = 5ms)
	time.Sleep(50 * time.Millisecond)

	// The background cleanup loop should have removed the expired session
	if sm.Count() != 0 {
		t.Errorf("Expected count 0 after automatic cleanup, got %d", sm.Count())
	}
}

// TestSessionManager_SessionNotFound tests resume with unknown session
func TestSessionManager_SessionNotFound(t *testing.T) {
	ctx := context.Background()
	sm := NewSessionManager(ctx, "127.0.0.1:22", 5*time.Minute, 0, DefaultBufferSize, noopLogf)

	unknownID, _ := NewSessionID()
	resumeFrame := &ResumeSessionFrame{SessionID: unknownID, LastSentSeq: 0, LastRecvSeq: 0}
	_, _, err := sm.HandleResumeSession(resumeFrame, "127.0.0.1:12345")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got %v", err)
	}
}

// TestClientSession_SendDataNotConnected tests error when not connected
func TestClientSession_SendDataNotConnected(t *testing.T) {
	cs, _ := NewClientSession(DefaultBufferSize, noopLogf)
	ctx := context.Background()

	err := cs.SendData(ctx, []byte("test"))
	if err == nil {
		t.Error("Expected error when not connected")
	}
}

// TestSession_Close tests session close
func TestSession_Close(t *testing.T) {
	sess, _ := NewSession(DefaultBufferSize)

	if sess.IsClosed() {
		t.Error("Session should not be closed initially")
	}

	sess.Close("test reason")

	if !sess.IsClosed() {
		t.Error("Session should be closed")
	}
}

// TestSession_ResumeState tests getting resume state
func TestSession_ResumeState(t *testing.T) {
	sess, _ := NewSession(DefaultBufferSize)

	// Send some data
	sess.PrepareData([]byte("a"))
	sess.PrepareData([]byte("b"))
	sess.PrepareData([]byte("c"))

	// Receive some data
	sess.HandleData(&DataFrame{Seq: 1, Payload: []byte("x")})
	sess.HandleData(&DataFrame{Seq: 2, Payload: []byte("y")})

	lastSent, lastRecv := sess.ResumeState()
	if lastSent != 3 {
		t.Errorf("Expected lastSent 3, got %d", lastSent)
	}
	if lastRecv != 2 {
		t.Errorf("Expected lastRecv 2, got %d", lastRecv)
	}
}

// TestMultipleDataFrames tests sending multiple data frames in sequence
func TestMultipleDataFrames(t *testing.T) {
	cs, _ := NewClientSession(DefaultBufferSize, noopLogf)
	stream := newMockStream()
	cs.Connect(stream)

	ctx := context.Background()
	stream.writeBuf.Reset()

	// Send multiple frames
	for i := 0; i < 5; i++ {
		if err := cs.SendData(ctx, []byte{byte(i)}); err != nil {
			t.Fatalf("SendData %d failed: %v", i, err)
		}
	}

	// Read them back
	for i := 1; i <= 5; i++ {
		frame, err := ReadFrame(stream.writeBuf)
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}
		data, ok := frame.(*DataFrame)
		if !ok {
			t.Fatalf("Expected DataFrame, got %T", frame)
		}
		if data.Seq != uint64(i) {
			t.Errorf("Frame %d: expected seq %d, got %d", i, i, data.Seq)
		}
	}
}
