package common

import (
	"testing"
)

func TestGetBuffer(t *testing.T) {
	buf := GetBuffer()
	if len(buf) != BufferSize {
		t.Fatalf("GetBuffer size = %d, want %d", len(buf), BufferSize)
	}
	// Fill with data
	for i := range buf {
		buf[i] = byte(i % 256)
	}

	// Don't put back to pool since subsequent calls reuse the buffer
}

func TestPutBuffer(t *testing.T) {
	buf := make([]byte, BufferSize)
	// Fill with data
	for i := range buf {
		buf[i] = byte(i)
	}

	// Put back to pool (should succeed because len matches BufferSize)
	PutBuffer(buf)
}

func TestPutBufferWrongSize(t *testing.T) {
	// Buffer with wrong size should be rejected
	buf := make([]byte, 1024)
	PutBuffer(buf) // should silently skip
}

func TestPutBufferZeroLen(t *testing.T) {
	// nil or zero-length slice
	PutBuffer(nil)      // len=0 != BufferSize, should skip
	PutBuffer([]byte{}) // same
}

func TestBufferPoolReuse(t *testing.T) {
	buf1 := GetBuffer()
	if len(buf1) != BufferSize {
		t.Fatalf("first GetBuffer size = %d", len(buf1))
	}
	// Mark it
	buf1[0] = 0xAB

	// Put back
	PutBuffer(buf1)

	// Get again - may or may not be the same buffer from pool
	buf2 := GetBuffer()
	if len(buf2) != BufferSize {
		t.Fatalf("second GetBuffer size = %d", len(buf2))
	}
	// Don't assert on content - pool may return a new buffer
}
