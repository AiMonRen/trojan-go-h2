package common

import (
	"io"
	"net"
	"sync"

	"github.com/voidluo/trojan-go/log"
)

type RewindReader struct {
	mu         sync.Mutex
	rawReader  io.Reader
	buf        []byte
	bufReadIdx int
	rewound    bool
	buffering  bool
	bufferSize int
}

func (r *RewindReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.rewound {
		if len(r.buf) > r.bufReadIdx {
			n := copy(p, r.buf[r.bufReadIdx:])
			r.bufReadIdx += n
			r.mu.Unlock()
			return n, nil
		}
		r.rewound = false // all buffering content has been read
	}
	buffering := r.buffering
	r.mu.Unlock()

	// 真正执行网络/底层的耗时阻塞读时，完全释放互斥锁
	n, err := r.rawReader.Read(p)

	if buffering && n > 0 {
		r.mu.Lock()
		// 重新确认结构体真实缓冲状态，防止在 rawReader.Read 阻塞期间被 StopBuffering() 并发调用
		if r.buffering {
			if len(r.buf)+n > 1024*1024 {
				r.mu.Unlock()
				return n, NewError("RewindReader buffer size exceeded 1MB limit")
			}
			r.buf = append(r.buf, p[:n]...)
			if len(r.buf) > r.bufferSize*2 {
				log.Debug("read too many bytes!")
			}
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *RewindReader) ReadByte() (byte, error) {
	buf := [1]byte{}
	_, err := r.Read(buf[:])
	return buf[0], err
}

func (r *RewindReader) Discard(n int) (int, error) {
	if n < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	buf := [128]byte{}
	discarded := 0
	for discarded < n {
		want := n - discarded
		if want > len(buf) {
			want = len(buf)
		}
		read, err := r.Read(buf[:want])
		discarded += read
		if err != nil {
			return discarded, err
		}
		if read == 0 {
			return discarded, io.ErrUnexpectedEOF
		}
	}
	return discarded, nil
}

func (r *RewindReader) Rewind() {
	r.mu.Lock()
	if r.bufferSize == 0 {
		panic("no buffer")
	}
	r.rewound = true
	r.bufReadIdx = 0
	r.mu.Unlock()
}

func (r *RewindReader) StopBuffering() {
	r.mu.Lock()
	r.buffering = false
	r.mu.Unlock()
}

func (r *RewindReader) SetBufferSize(size int) {
	r.mu.Lock()
	if size == 0 { // disable buffering
		if !r.buffering {
			panic("reader is disabled")
		}
		r.buffering = false
		r.buf = nil
		r.bufReadIdx = 0
		r.bufferSize = 0
	} else {
		if r.buffering {
			panic("reader is buffering")
		}
		r.buffering = true
		r.bufReadIdx = 0
		r.bufferSize = size
		r.buf = make([]byte, 0, size)
	}
	r.mu.Unlock()
}

type RewindConn struct {
	net.Conn
	*RewindReader
}

func (c *RewindConn) Read(p []byte) (int, error) {
	return c.RewindReader.Read(p)
}

func NewRewindConn(conn net.Conn) *RewindConn {
	return &RewindConn{
		Conn: conn,
		RewindReader: &RewindReader{
			rawReader: conn,
		},
	}
}

type StickyWriter struct {
	rawWriter   io.Writer
	writeBuffer []byte
	MaxBuffered int
}

func (w *StickyWriter) Write(p []byte) (int, error) {
	if w.MaxBuffered > 0 {
		w.MaxBuffered--
		w.writeBuffer = append(w.writeBuffer, p...)
		if w.MaxBuffered != 0 {
			return len(p), nil
		}
		w.MaxBuffered = 0
		_, err := w.rawWriter.Write(w.writeBuffer)
		w.writeBuffer = nil
		return len(p), err
	}
	return w.rawWriter.Write(p)
}
