package common

import "sync"

const (
	BufferSize = 32 * 1024
)

var pool = sync.Pool{
	New: func() any {
		return make([]byte, BufferSize)
	},
}

func GetBuffer() []byte {
	return pool.Get().([]byte)
}

func PutBuffer(buf []byte) {
	if len(buf) != BufferSize {
		return
	}
	clear(buf[:min(len(buf), 2048)])
	pool.Put(buf)
}
