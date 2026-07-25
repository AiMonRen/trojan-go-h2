package webserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/voidluo/trojan-go/log"
)

// ServiceRouter consumes already-decrypted HTTP connections from the Trojan TLS
// listener and forwards only recognized control-plane paths to loopback services.
// Trojan protocol connections never enter this router.
type ServiceRouter struct {
	adminPrefix   string
	subPath       string
	adminDisabled bool
	connChan      chan net.Conn
	done          chan struct{}
	closeOnce     sync.Once
	httpServer    *http.Server
	// activeConns tracks connections handed to the embedded HTTP server so a
	// bounded drain can forcibly close whatever is still open once the deadline
	// elapses, instead of leaking connections and their goroutines.
	activeConns map[net.Conn]struct{}
	connMu      sync.Mutex
}

func NewServiceRouter(adminAddress, controlAddress, adminPrefix, subPath string) (*ServiceRouter, error) {
	var adminTarget *url.URL
	var err error
	adminDisabled := adminAddress == ""
	if !adminDisabled {
		adminTarget, err = loopbackHTTPURL(adminAddress, "admin-service")
		if err != nil {
			return nil, err
		}
	}
	controlTarget, err := loopbackHTTPURL(controlAddress, "control-service")
	if err != nil {
		return nil, err
	}
	if adminPrefix == "" {
		adminPrefix = "/admin/"
	}
	if !strings.HasPrefix(adminPrefix, "/") {
		adminPrefix = "/" + adminPrefix
	}
	if !strings.HasSuffix(adminPrefix, "/") {
		adminPrefix += "/"
	}
	if subPath == "" {
		subPath = "/sub"
	}
	if !strings.HasPrefix(subPath, "/") {
		subPath = "/" + subPath
	}

	router := &ServiceRouter{
		adminPrefix:   adminPrefix,
		subPath:       subPath,
		adminDisabled: adminDisabled,
		connChan:      make(chan net.Conn, 64),
		done:          make(chan struct{}),
		activeConns:   make(map[net.Conn]struct{}),
	}
	mux := http.NewServeMux()
	mux.Handle("/control/v1/", newSanitizedReverseProxy(controlTarget))
	if !adminDisabled {
		adminProxy := newSanitizedReverseProxy(adminTarget)
		mux.Handle(adminPrefix, adminProxy)
		mux.Handle(strings.TrimSuffix(adminPrefix, "/"), adminProxy)
		mux.Handle("/sub", adminProxy)
		if subPath != "/sub" {
			mux.Handle(subPath, adminProxy)
		}
	}
	router.httpServer = newHTTPServer(mux)
	// Track live connections through the HTTP server's own state machine so the
	// bounded drain in Close knows exactly what is still open.
	router.httpServer.ConnState = func(conn net.Conn, state http.ConnState) {
		router.connMu.Lock()
		switch state {
		case http.StateNew:
			router.activeConns[conn] = struct{}{}
		case http.StateClosed, http.StateHijacked:
			delete(router.activeConns, conn)
		}
		router.connMu.Unlock()
	}
	go func() {
		_ = router.httpServer.Serve(router)
	}()
	return router, nil
}

func newSanitizedReverseProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	baseDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		baseDirector(request)
		request.Header.Del("Forwarded")
		request.Header.Del("X-Forwarded-For")
		request.Header.Del("X-Forwarded-Host")
		request.Header.Del("X-Forwarded-Proto")
		request.Header.Del("X-Real-IP")
	}
	return proxy
}

func loopbackHTTPURL(address, serviceName string) (*url.URL, error) {
	target, err := url.Parse("http://" + address)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("invalid %s address %q", serviceName, address)
	}
	host := target.Hostname()
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		return nil, fmt.Errorf("%s must use a loopback address, got %q", serviceName, address)
	}
	return target, nil
}

func (r *ServiceRouter) Matches(path string) bool {
	if strings.HasPrefix(path, "/control/v1/") {
		return true
	}
	if r.adminDisabled {
		return false
	}
	adminRoot := strings.TrimSuffix(r.adminPrefix, "/")
	return path == r.subPath || path == "/sub" || path == adminRoot || strings.HasPrefix(path, r.adminPrefix)
}

func (r *ServiceRouter) ServeConn(conn net.Conn) {
	select {
	case r.connChan <- conn:
	case <-r.done:
		_ = conn.Close()
	}
}

func (r *ServiceRouter) Accept() (net.Conn, error) {
	select {
	case conn := <-r.connChan:
		return conn, nil
	case <-r.done:
		return nil, net.ErrClosed
	}
}

func (r *ServiceRouter) Close() error {
	r.closeOnce.Do(func() {
		// Closing done makes Accept return net.ErrClosed so the HTTP server
		// stops accepting new connections.
		close(r.done)

		// Bounded drain: give in-flight requests up to the drain timeout to
		// finish via graceful Shutdown, then forcibly close whatever is still
		// open. Shutdown runs in its own goroutine because it calls the
		// listener's Close (this ServiceRouter); invoking it inline would
		// re-enter closeOnce.Do on the same goroutine and deadlock.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), GatewayDrainTimeout)
		defer cancel()
		shutdownDone := make(chan struct{})
		go func() {
			_ = r.httpServer.Shutdown(shutdownCtx)
			close(shutdownDone)
		}()
		select {
		case <-shutdownDone:
		case <-shutdownCtx.Done():
			forced := r.forceCloseActiveConns()
			if forced > 0 {
				log.Warnf("service-router: drain deadline exceeded with %d connections still active, forcing close", forced)
			}
		}
	})
	return nil
}

// forceCloseActiveConns closes every connection the HTTP server still holds,
// plus any that were queued but not yet accepted, so nothing is leaked.
func (r *ServiceRouter) forceCloseActiveConns() int {
	r.connMu.Lock()
	conns := make([]net.Conn, 0, len(r.activeConns))
	for conn := range r.activeConns {
		conns = append(conns, conn)
	}
	r.connMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	// Drain connections still queued in connChan that the HTTP server never
	// got to accept before Shutdown stopped it.
	for {
		select {
		case conn := <-r.connChan:
			_ = conn.Close()
			conns = append(conns, conn)
		default:
			return len(conns)
		}
	}
}

func (r *ServiceRouter) Addr() net.Addr { return &net.TCPAddr{} }
