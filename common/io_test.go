package common

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	v2common "github.com/v2fly/v2ray-core/v4/common"
)

func TestBufferedReader(t *testing.T) {
	payload := [1024]byte{}
	rand.Reader.Read(payload[:])
	r := RewindReader{rawReader: bytes.NewBuffer(payload[:])}
	r.SetBufferSize(2048)
	buf1 := make([]byte, 512)
	buf2 := make([]byte, 512)
	v2common.Must2(r.Read(buf1))
	r.Rewind()
	v2common.Must2(r.Read(buf2))
	if !bytes.Equal(buf1, buf2) {
		t.Fatal("rewound bytes differ")
	}
	buf3 := make([]byte, 512)
	v2common.Must2(r.Read(buf3))
	if !bytes.Equal(buf3, payload[512:]) {
		t.Fatal("remaining bytes differ")
	}
	r.Rewind()
	buf4 := make([]byte, 1024)
	v2common.Must2(r.Read(buf4))
	if !bytes.Equal(payload[:], buf4) {
		t.Fatal("full rewind differs")
	}
}

func TestRewindReaderDiscardBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 127, 128, 129, 255, 256, 257} {
		r := &RewindReader{rawReader: bytes.NewReader(bytes.Repeat([]byte{'x'}, size))}
		discarded, err := r.Discard(size)
		if err != nil || discarded != size {
			t.Errorf("Discard(%d) = (%d, %v)", size, discarded, err)
		}
	}
}

func TestRewindReaderDiscardShortRead(t *testing.T) {
	r := &RewindReader{rawReader: bytes.NewReader([]byte("abc"))}
	discarded, err := r.Discard(4)
	if discarded != 3 || err != io.EOF {
		t.Fatalf("Discard short read = (%d, %v), want (3, EOF)", discarded, err)
	}
}

func TestRewindReaderDiscardNegative(t *testing.T) {
	r := &RewindReader{rawReader: bytes.NewReader(nil)}
	if discarded, err := r.Discard(-1); discarded != 0 || err == nil {
		t.Fatalf("Discard(-1) = (%d, %v), want an error", discarded, err)
	}
}

func TestRewindReaderDiscardZero(t *testing.T) {
	r := &RewindReader{rawReader: bytes.NewReader(nil)}
	if discarded, err := r.Discard(0); discarded != 0 || err != nil {
		t.Fatalf("Discard(0) = (%d, %v)", discarded, err)
	}
}
