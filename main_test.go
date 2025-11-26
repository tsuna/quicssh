package main

import (
"bytes"
"context"
"errors"
"io"
"testing"
)

func TestReadAndWrite_BasicCopy(t *testing.T) {
	ctx := context.Background()
	data := []byte("hello world")
	r := bytes.NewReader(data)
	w := &bytes.Buffer{}

	errCh := readAndWrite(ctx, r, w)
	err := <-errCh

	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
	if !bytes.Equal(w.Bytes(), data) {
		t.Errorf("data mismatch: got %q, want %q", w.Bytes(), data)
	}
}

func TestReadAndWrite_LargeData(t *testing.T) {
	ctx := context.Background()
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	r := bytes.NewReader(data)
	w := &bytes.Buffer{}

	errCh := readAndWrite(ctx, r, w)
	err := <-errCh

	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
	if !bytes.Equal(w.Bytes(), data) {
		t.Errorf("data mismatch: lengths got %d, want %d", len(w.Bytes()), len(data))
	}
}

func TestReadAndWrite_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &slowReader{data: make([]byte, 1024*1024), cancel: cancel}
	w := &bytes.Buffer{}

	errCh := readAndWrite(ctx, r, w)
	err := <-errCh

	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

type slowReader struct {
	data   []byte
	offset int
	cancel context.CancelFunc
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	if r.offset > 0 && r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func TestReadAndWrite_WriteError(t *testing.T) {
	ctx := context.Background()
	data := []byte("hello world")
	r := bytes.NewReader(data)
	expectedErr := errors.New("write failed")
	w := &errorWriter{err: expectedErr}

	errCh := readAndWrite(ctx, r, w)
	err := <-errCh

	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

type errorWriter struct {
	err error
}

func (w *errorWriter) Write(p []byte) (int, error) {
	return 0, w.err
}

func TestReadAndWrite_ShortWrite(t *testing.T) {
	ctx := context.Background()
	data := []byte("hello world")
	r := bytes.NewReader(data)
	w := &shortWriter{}

	errCh := readAndWrite(ctx, r, w)
	err := <-errCh

	if err != io.ErrShortWrite {
		t.Errorf("expected io.ErrShortWrite, got %v", err)
	}
}

type shortWriter struct{}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		return 1, nil
	}
	return len(p), nil
}

func BenchmarkReadAndWrite_1MB(b *testing.B) {
	data := make([]byte, 1024*1024)
	ctx := context.Background()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		w := &bytes.Buffer{}
		errCh := readAndWrite(ctx, r, w)
		<-errCh
	}
}

func BenchmarkReadAndWrite_10MB(b *testing.B) {
	data := make([]byte, 10*1024*1024)
	ctx := context.Background()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		w := &bytes.Buffer{}
		errCh := readAndWrite(ctx, r, w)
		<-errCh
	}
}

func BenchmarkReadAndWrite_50MB(b *testing.B) {
	data := make([]byte, 50*1024*1024)
	ctx := context.Background()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		w := &bytes.Buffer{}
		errCh := readAndWrite(ctx, r, w)
		<-errCh
	}
}
