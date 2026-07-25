package option

import (
	"sync"

	"github.com/voidluo/trojan-go/common"
)

type Handler interface {
	Name() string
	Handle() error
	Priority() int
}

var (
	handlers   = make(map[string]Handler)
	handlersMu sync.Mutex
)

// RegisterHandler registers an option handler. It is safe for concurrent use
// but intended to be called during init().
func RegisterHandler(h Handler) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	handlers[h.Name()] = h
}

// PopOptionHandler pops the highest-priority registered handler. It is safe for
// concurrent use.
func PopOptionHandler() (Handler, error) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	var maxHandler Handler = nil
	for _, h := range handlers {
		if maxHandler == nil || maxHandler.Priority() < h.Priority() {
			maxHandler = h
		}
	}
	if maxHandler == nil {
		return nil, common.NewError("no option left")
	}
	delete(handlers, maxHandler.Name())
	return maxHandler, nil
}
