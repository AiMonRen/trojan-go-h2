package common

import "sync"

const (
	// BufferSize is the io.CopyBuffer chunk size used for proxy relay.
	// 64KB improves throughput on high-BDP (Bandwidth-Delay Product) links
	// such as cross-ISP domestic routing or long-haul international paths.
	BufferSize = 64 * 1024
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
