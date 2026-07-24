package trojan

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/statistic"
)

type dataPlaneTraffic struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type dataPlaneTrafficBatch struct {
	SyncID  string                      `json:"sync_id"`
	Traffic map[string]dataPlaneTraffic `json:"traffic"`
}

type dataPlaneTrafficReporter struct {
	mu       sync.Mutex
	auth     statistic.Authenticator
	endpoint string
	client   *http.Client
	pending  *dataPlaneTrafficBatch
}

func newDataPlaneTrafficReporter(auth statistic.Authenticator, endpoint string) (*dataPlaneTrafficReporter, error) {
	target, err := url.Parse(endpoint)
	if err != nil || target.Scheme != "http" || target.Host == "" {
		return nil, fmt.Errorf("invalid data-plane traffic endpoint %q", endpoint)
	}
	host := target.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("data-plane traffic endpoint must use loopback, got %q", endpoint)
	}
	return &dataPlaneTrafficReporter{
		auth:     auth,
		endpoint: target.String(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (r *dataPlaneTrafficReporter) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := r.flush(ctx); err != nil {
				log.Warnf("trojan data-plane traffic report failed: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (r *dataPlaneTrafficReporter) flush(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		batch, err := r.collect()
		if err != nil {
			return err
		}
		if batch == nil {
			return nil
		}
		r.pending = batch
	}
	body, err := json.Marshal(r.pending)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("traffic endpoint returned HTTP %d", response.StatusCode)
	}
	r.pending = nil
	return nil
}

func (r *dataPlaneTrafficReporter) collect() (*dataPlaneTrafficBatch, error) {
	traffic := make(map[string]dataPlaneTraffic)
	for _, user := range r.auth.ListUsers() {
		sent, received := user.ResetTraffic()
		if sent == 0 && received == 0 {
			continue
		}
		// Client upload is server receive; client download is server send.
		traffic[user.Hash()] = dataPlaneTraffic{Up: received, Down: sent}
	}
	if len(traffic) == 0 {
		return nil, nil
	}
	syncID, err := newDataPlaneTrafficSyncID()
	if err != nil {
		// Restore counters so random-source failure cannot lose accounting.
		for hash, value := range traffic {
			if ok, user := r.auth.AuthUser(hash); ok {
				user.AddTraffic(int(value.Down), int(value.Up))
			}
		}
		return nil, err
	}
	return &dataPlaneTrafficBatch{SyncID: syncID, Traffic: traffic}, nil
}

func newDataPlaneTrafficSyncID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := cryptorand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate data-plane traffic sync id: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}
