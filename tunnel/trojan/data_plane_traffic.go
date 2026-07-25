package trojan

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/voidluo/trojan-go/internal/trafficoutbox"
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
	mu            sync.Mutex
	auth          statistic.Authenticator
	endpoint      string
	client        *http.Client
	pending       *dataPlaneTrafficBatch
	queued        map[string]dataPlaneTraffic
	outbox        *trafficoutbox.File
	loadErr       error
	internalToken string
}

func newDataPlaneTrafficReporter(auth statistic.Authenticator, endpoint string, internalTokenPath string, outboxPath ...string) (*dataPlaneTrafficReporter, error) {
	target, err := url.Parse(endpoint)
	if err != nil || target.Scheme != "http" || target.Host == "" {
		return nil, fmt.Errorf("invalid data-plane traffic endpoint %q", endpoint)
	}
	host := target.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("data-plane traffic endpoint must use loopback, got %q", endpoint)
	}
	var path string
	if len(outboxPath) > 0 {
		path = outboxPath[0]
	}
	outbox, err := trafficoutbox.NewFile(path)
	if err != nil {
		return nil, err
	}
	token, tokenErr := readInternalToken(internalTokenPath)
	if tokenErr != nil && internalTokenPath != "" {
		return nil, fmt.Errorf("read internal token for data-plane traffic: %w", tokenErr)
	}
	reporter := &dataPlaneTrafficReporter{
		auth:          auth,
		endpoint:      target.String(),
		client:        &http.Client{Timeout: 10 * time.Second},
		queued:        make(map[string]dataPlaneTraffic),
		outbox:        outbox,
		internalToken: token,
	}
	if err := reporter.loadOutbox(); err != nil {
		reporter.loadErr = err
	}
	return reporter, nil
}

func (r *dataPlaneTrafficReporter) loadOutbox() error {
	if r.outbox == nil {
		return nil
	}
	state, err := r.outbox.Load()
	if err != nil {
		return err
	}
	if len(state.Pending) > 0 {
		r.pending = &dataPlaneTrafficBatch{SyncID: state.PendingSyncID, Traffic: fromDataPlaneOutboxTraffic(state.Pending)}
	}
	r.queued = fromDataPlaneOutboxTraffic(state.Queued)
	return nil
}

func toDataPlaneOutboxTraffic(source map[string]dataPlaneTraffic) map[string]trafficoutbox.Traffic {
	result := make(map[string]trafficoutbox.Traffic, len(source))
	for hash, value := range source {
		result[hash] = trafficoutbox.Traffic{Up: value.Up, Down: value.Down}
	}
	return result
}

func fromDataPlaneOutboxTraffic(source map[string]trafficoutbox.Traffic) map[string]dataPlaneTraffic {
	result := make(map[string]dataPlaneTraffic, len(source))
	for hash, value := range source {
		result[hash] = dataPlaneTraffic{Up: value.Up, Down: value.Down}
	}
	return result
}

func (r *dataPlaneTrafficReporter) persistOutbox() error {
	if r.outbox == nil {
		return nil
	}
	state := trafficoutbox.State{Queued: toDataPlaneOutboxTraffic(r.queued)}
	if r.pending != nil {
		state.PendingSyncID = r.pending.SyncID
		state.Pending = toDataPlaneOutboxTraffic(r.pending.Traffic)
	}
	return r.outbox.Save(state)
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
	if r.loadErr != nil {
		return fmt.Errorf("traffic outbox unavailable: %w", r.loadErr)
	}
	if err := r.collect(); err != nil {
		return err
	}
	if r.pending == nil && len(r.queued) > 0 {
		syncID, err := newDataPlaneTrafficSyncID()
		if err != nil {
			return err
		}
		oldQueued := r.queued
		r.pending = &dataPlaneTrafficBatch{SyncID: syncID, Traffic: oldQueued}
		r.queued = make(map[string]dataPlaneTraffic)
		if err := r.persistOutbox(); err != nil {
			r.pending = nil
			r.queued = oldQueued
			return fmt.Errorf("freeze data-plane traffic batch: %w", err)
		}
	}
	if r.pending == nil {
		return nil
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
	if r.internalToken != "" {
		request.Header.Set("X-Internal-Token", r.internalToken)
	}
	response, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("traffic endpoint returned HTTP %d", response.StatusCode)
	}
	accepted := r.pending
	r.pending = nil
	if err := r.persistOutbox(); err != nil {
		r.pending = accepted
		return fmt.Errorf("acknowledge data-plane traffic batch: %w", err)
	}
	return nil
}

func (r *dataPlaneTrafficReporter) collect() error {
	if r.queued == nil {
		r.queued = make(map[string]dataPlaneTraffic)
	}
	for _, user := range r.auth.ListUsers() {
		hash := user.Hash()
		_, _, err := user.TakeTraffic(func(sent, received uint64) error {
			current, existed := r.queued[hash]
			if current.Up > ^uint64(0)-received || current.Down > ^uint64(0)-sent {
				return fmt.Errorf("data-plane traffic aggregation overflow for user %s", hash)
			}
			r.queued[hash] = dataPlaneTraffic{Up: current.Up + received, Down: current.Down + sent}
			if err := r.persistOutbox(); err != nil {
				if existed {
					r.queued[hash] = current
				} else {
					delete(r.queued, hash)
				}
				return fmt.Errorf("checkpoint data-plane traffic for user %s: %w", hash, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func newDataPlaneTrafficSyncID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := cryptorand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate data-plane traffic sync id: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func readInternalToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read internal token file %s: %w", path, err)
	}
	token := string(data)
	if len(token) < 16 {
		return "", fmt.Errorf("internal token file %s is too short (%d bytes)", path, len(token))
	}
	return token, nil
}
