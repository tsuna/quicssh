package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Frame types for the session layer protocol.
// This protocol sits on top of QUIC streams and provides session resumption
// capabilities that survive QUIC connection failures and IP changes.
const (
	FrameTypeNewSession    uint8 = 0x01 // Client initiates a new session
	FrameTypeResumeSession uint8 = 0x02 // Client resumes an existing session
	FrameTypeResumeAck     uint8 = 0x03 // Server acknowledges resume request
	FrameTypeData          uint8 = 0x04 // Data payload with sequence number
	FrameTypeAck           uint8 = 0x05 // Acknowledges received data up to sequence
	FrameTypeClose         uint8 = 0x06 // Graceful session close
)

// dataFrameHeaderSize is the size of the DataFrame header (type + seq + length).
const dataFrameHeaderSize = 1 + 8 + 2 // 11 bytes

// dataFrameBufferSize is the size of buffer needed for encoding DataFrames.
// It holds the header plus max payload (64KB).
const dataFrameBufferSize = dataFrameHeaderSize + 65535

// SessionID is a unique identifier for a session (UUID).
type SessionID [16]byte

// NewSessionID generates a new random SessionID.
func NewSessionID() (SessionID, error) {
	var id SessionID
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("failed to generate session ID: %w", err)
	}
	return id, nil
}

// String returns a hex-encoded string representation of the SessionID.
func (id SessionID) String() string {
	return hex.EncodeToString(id[:])
}

// IsZero returns true if the SessionID is all zeros.
func (id SessionID) IsZero() bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

// Frame is the interface implemented by all frame types.
type Frame interface {
	Type() uint8
	// Encode writes the frame to w. The buf parameter is a scratch buffer that
	// may be used for encoding (must be at least DataFrameBufferSize bytes).
	// Some frame types may ignore buf and use stack-allocated arrays instead.
	Encode(w io.Writer, buf []byte) error
}

// NewSessionFrame is sent by the client to initiate a new session.
type NewSessionFrame struct {
	SessionID SessionID
}

func (f *NewSessionFrame) Type() uint8 { return FrameTypeNewSession }

func (f *NewSessionFrame) Encode(w io.Writer, _ []byte) error {
	var buf [1 + 16]byte // 1 byte type + 16 bytes SessionID
	buf[0] = f.Type()
	copy(buf[1:], f.SessionID[:])
	_, err := w.Write(buf[:])
	return err
}

// ResumeSessionFrame is sent by the client to resume an existing session.
type ResumeSessionFrame struct {
	SessionID   SessionID
	LastSentSeq uint64 // Last sequence number sent by client (for server to know where client's buffer starts)
	LastRecvSeq uint64 // Last sequence number received by client (for server to replay from)
}

func (f *ResumeSessionFrame) Type() uint8 { return FrameTypeResumeSession }

func (f *ResumeSessionFrame) Encode(w io.Writer, _ []byte) error {
	var buf [1 + 16 + 8 + 8]byte // 1 type + 16 SessionID + 8 LastSentSeq + 8 LastRecvSeq
	buf[0] = f.Type()
	copy(buf[1:17], f.SessionID[:])
	binary.BigEndian.PutUint64(buf[17:25], f.LastSentSeq)
	binary.BigEndian.PutUint64(buf[25:33], f.LastRecvSeq)
	_, err := w.Write(buf[:])
	return err
}

// ResumeAckFrame is sent by the server in response to ResumeSessionFrame.
type ResumeAckFrame struct {
	LastRecvSeq uint64 // Last sequence number received by server (client should replay from here+1)
	LastSentSeq uint64 // Last sequence number sent by server (client should expect from here+1)
}

func (f *ResumeAckFrame) Type() uint8 { return FrameTypeResumeAck }

func (f *ResumeAckFrame) Encode(w io.Writer, _ []byte) error {
	var buf [1 + 8 + 8]byte // 1 type + 8 LastRecvSeq + 8 LastSentSeq
	buf[0] = f.Type()
	binary.BigEndian.PutUint64(buf[1:9], f.LastRecvSeq)
	binary.BigEndian.PutUint64(buf[9:17], f.LastSentSeq)
	_, err := w.Write(buf[:])
	return err
}

// DataFrame carries data with a sequence number.
type DataFrame struct {
	Seq     uint64 // Sequence number (monotonically increasing per direction)
	Payload []byte // Data payload (max 64KB to fit in uint16 length prefix)
}

func (f *DataFrame) Type() uint8 { return FrameTypeData }

// Encode encodes the DataFrame using the provided buffer.
// The buffer must be at least DataFrameBufferSize bytes.
func (f *DataFrame) Encode(w io.Writer, buf []byte) error {
	payloadLen := len(f.Payload)
	if payloadLen > 65535 {
		return errors.New("payload too large (max 65535 bytes)")
	}

	// Compose the entire frame in the buffer
	buf[0] = f.Type()
	binary.BigEndian.PutUint64(buf[1:9], f.Seq)
	binary.BigEndian.PutUint16(buf[9:11], uint16(payloadLen))
	copy(buf[dataFrameHeaderSize:], f.Payload)

	// Single write for the entire frame
	_, err := w.Write(buf[:dataFrameHeaderSize+payloadLen])
	return err
}

// AckFrame acknowledges receipt of data up to a sequence number.
type AckFrame struct {
	Seq uint64 // All data up to and including this sequence has been received
}

func (f *AckFrame) Type() uint8 { return FrameTypeAck }

func (f *AckFrame) Encode(w io.Writer, _ []byte) error {
	var buf [9]byte // 1 byte type + 8 bytes seq
	buf[0] = f.Type()
	binary.BigEndian.PutUint64(buf[1:9], f.Seq)
	_, err := w.Write(buf[:])
	return err
}

// CloseFrame signals graceful session termination.
type CloseFrame struct {
	Reason string // Optional reason for closing (max 255 bytes)
}

func (f *CloseFrame) Type() uint8 { return FrameTypeClose }

func (f *CloseFrame) Encode(w io.Writer, _ []byte) error {
	reasonLen := len(f.Reason)
	if reasonLen > 255 {
		return errors.New("close reason too long (max 255 bytes)")
	}
	// Use stack-allocated buffer for header + reason (max 257 bytes)
	var buf [1 + 1 + 255]byte // 1 type + 1 length + max 255 reason
	buf[0] = f.Type()
	buf[1] = uint8(reasonLen)
	copy(buf[2:], f.Reason)
	_, err := w.Write(buf[:2+reasonLen])
	return err
}

// ErrUnknownFrameType is returned when an unknown frame type is encountered.
var ErrUnknownFrameType = errors.New("unknown frame type")

// ErrSessionLayerMismatch is returned when raw SSH protocol is detected instead of session frames.
// This typically happens when the client uses --session-layer but the server does not.
var ErrSessionLayerMismatch = errors.New("received SSH protocol instead of session frame: client and server must both use --session-layer or both not use it")

// ErrSessionNotFound is returned when trying to resume a non-existent session.
var ErrSessionNotFound = errors.New("session not found")

// ReadFrame reads and decodes a frame from the reader.
func ReadFrame(r io.Reader) (Frame, error) {
	var frameType uint8
	if err := binary.Read(r, binary.BigEndian, &frameType); err != nil {
		return nil, err
	}

	switch frameType {
	case FrameTypeNewSession:
		return readNewSessionFrame(r)
	case FrameTypeResumeSession:
		return readResumeSessionFrame(r)
	case FrameTypeResumeAck:
		return readResumeAckFrame(r)
	case FrameTypeData:
		return readDataFrame(r)
	case FrameTypeAck:
		return readAckFrame(r)
	case FrameTypeClose:
		return readCloseFrame(r)
	case 'S': // 0x53 = 'S' from "SSH-2.0-..." banner
		return nil, ErrSessionLayerMismatch
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownFrameType, frameType)
	}
}

func readNewSessionFrame(r io.Reader) (*NewSessionFrame, error) {
	f := &NewSessionFrame{}
	if _, err := io.ReadFull(r, f.SessionID[:]); err != nil {
		return nil, err
	}
	return f, nil
}

func readResumeSessionFrame(r io.Reader) (*ResumeSessionFrame, error) {
	f := &ResumeSessionFrame{}
	if _, err := io.ReadFull(r, f.SessionID[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &f.LastSentSeq); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &f.LastRecvSeq); err != nil {
		return nil, err
	}
	return f, nil
}

func readResumeAckFrame(r io.Reader) (*ResumeAckFrame, error) {
	f := &ResumeAckFrame{}
	if err := binary.Read(r, binary.BigEndian, &f.LastRecvSeq); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &f.LastSentSeq); err != nil {
		return nil, err
	}
	return f, nil
}

func readDataFrame(r io.Reader) (*DataFrame, error) {
	f := &DataFrame{}
	if err := binary.Read(r, binary.BigEndian, &f.Seq); err != nil {
		return nil, err
	}
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	f.Payload = make([]byte, length)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return nil, err
	}
	return f, nil
}

func readAckFrame(r io.Reader) (*AckFrame, error) {
	f := &AckFrame{}
	if err := binary.Read(r, binary.BigEndian, &f.Seq); err != nil {
		return nil, err
	}
	return f, nil
}

func readCloseFrame(r io.Reader) (*CloseFrame, error) {
	var length uint8
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	reason := make([]byte, length)
	if _, err := io.ReadFull(r, reason); err != nil {
		return nil, err
	}
	return &CloseFrame{Reason: string(reason)}, nil
}
