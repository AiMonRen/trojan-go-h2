package webserver

import (
	"net/http"
	"time"
)

const (
	// ServerReadHeaderTimeout prevents slow-header attacks by giving a
	// fixed window for the client to send the full request header.
	ServerReadHeaderTimeout = 10 * time.Second

	// ServerReadTimeout limits the time a client can take to send the
	// entire request body after the header has been received.
	ServerReadTimeout = 30 * time.Second

	// ServerWriteTimeout limits the time the server will wait when
	// writing a response to the client.
	ServerWriteTimeout = 30 * time.Second

	// ServerIdleTimeout controls how long a keep-alive connection may
	// remain idle before the server closes it.
	ServerIdleTimeout = 60 * time.Second

	// ServerMaxHeaderBytes caps the total size of all request headers,
	// preventing memory exhaustion from crafted large-headers.
	ServerMaxHeaderBytes = 1 << 16 // 64 KiB

	// MaxActiveConnections limits the number of concurrently accepted
	// connections (including those still in TLS handshake).
	MaxActiveConnections = 10000

	// GatewayDrainTimeout is the maximum duration to wait for in-flight
	// connections to finish during a graceful Gateway shutdown before
	// forcibly closing remaining connections.
	GatewayDrainTimeout = 30 * time.Second
)

// newHTTPServer returns an http.Server with safe timeout and header limits.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: ServerReadHeaderTimeout,
		ReadTimeout:       ServerReadTimeout,
		WriteTimeout:      ServerWriteTimeout,
		IdleTimeout:       ServerIdleTimeout,
		MaxHeaderBytes:    ServerMaxHeaderBytes,
	}
}
