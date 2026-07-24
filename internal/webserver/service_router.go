package webserver

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
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
	}
	mux := http.NewServeMux()
	mux.Handle("/control/v1/", httputil.NewSingleHostReverseProxy(controlTarget))
	if !adminDisabled {
		adminProxy := httputil.NewSingleHostReverseProxy(adminTarget)
		mux.Handle(adminPrefix, adminProxy)
		mux.Handle(strings.TrimSuffix(adminPrefix, "/"), adminProxy)
		mux.Handle("/sub", adminProxy)
		if subPath != "/sub" {
			mux.Handle(subPath, adminProxy)
		}
	}
	router.httpServer = &http.Server{Handler: mux}
	go func() {
		_ = router.httpServer.Serve(router)
	}()
	return router, nil
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
		close(r.done)
	})
	return nil
}

func (r *ServiceRouter) Addr() net.Addr { return &net.TCPAddr{} }
