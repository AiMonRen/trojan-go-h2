package memory

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/statistic"
)

const Name = "MEMORY"

type User struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent      uint64
	recv      uint64
	lastSent  uint64
	lastRecv  uint64
	sendSpeed uint64
	recvSpeed uint64

	hash        string
	trafficLock sync.Mutex
	ipLock      sync.Mutex
	ipTable     map[string]struct{}
	maxIPNum    int
	limiterLock sync.RWMutex
	sendLimiter *rate.Limiter
	recvLimiter *rate.Limiter
	ctx         context.Context
	cancel      context.CancelFunc
}

func (u *User) Close() error {
	u.ResetTraffic()
	u.cancel()
	return nil
}

func (u *User) AddIP(ip string) bool {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	if u.maxIPNum <= 0 {
		return true
	}
	if _, found := u.ipTable[ip]; found {
		return true
	}
	if len(u.ipTable) >= u.maxIPNum {
		return false
	}
	u.ipTable[ip] = struct{}{}
	return true
}

func (u *User) DelIP(ip string) bool {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	if u.maxIPNum <= 0 {
		return true
	}
	if _, found := u.ipTable[ip]; !found {
		return false
	}
	delete(u.ipTable, ip)
	return true
}

func (u *User) GetIP() int {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	return len(u.ipTable)
}

func (u *User) SetIPLimit(n int) {
	u.ipLock.Lock()
	u.maxIPNum = n
	if n <= 0 {
		clear(u.ipTable)
	}
	u.ipLock.Unlock()
}

func (u *User) GetIPLimit() int {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	return u.maxIPNum
}

func (u *User) AddTraffic(sent, recv int) {
	if sent < 0 || recv < 0 {
		return
	}
	u.limiterLock.RLock()
	defer u.limiterLock.RUnlock()

	if u.sendLimiter != nil && sent > 0 {
		u.sendLimiter.WaitN(u.ctx, sent)
	}
	if u.recvLimiter != nil && recv > 0 {
		u.recvLimiter.WaitN(u.ctx, recv)
	}
	u.AddTraffic64(uint64(sent), uint64(recv))
}

func (u *User) AddTraffic64(sent, recv uint64) {
	u.trafficLock.Lock()
	atomic.AddUint64(&u.sent, sent)
	atomic.AddUint64(&u.recv, recv)
	u.trafficLock.Unlock()
}

// SubtractTraffic atomically decreases the traffic counters by the given
// amounts, saturating at zero. It holds trafficLock to serialize against
// concurrent AddTraffic64 calls. This is used by the embedded sync path to
// close the crash window between ResetTraffic and the database commit:
// traffic is persisted first, then counters are decremented only on success.
func (u *User) SubtractTraffic(sent, recv uint64) {
	u.trafficLock.Lock()
	defer u.trafficLock.Unlock()
	cur := atomic.LoadUint64(&u.sent)
	if cur >= sent {
		atomic.StoreUint64(&u.sent, cur-sent)
	} else {
		atomic.StoreUint64(&u.sent, 0)
	}
	cur = atomic.LoadUint64(&u.recv)
	if cur >= recv {
		atomic.StoreUint64(&u.recv, cur-recv)
	} else {
		atomic.StoreUint64(&u.recv, 0)
	}
}

func (u *User) SetSpeedLimit(send, recv int) {
	u.limiterLock.Lock()
	defer u.limiterLock.Unlock()

	if send <= 0 {
		u.sendLimiter = nil
	} else {
		u.sendLimiter = rate.NewLimiter(rate.Limit(send), send*2)
	}
	if recv <= 0 {
		u.recvLimiter = nil
	} else {
		u.recvLimiter = rate.NewLimiter(rate.Limit(recv), recv*2)
	}
}

func (u *User) GetSpeedLimit() (send, recv int) {
	u.limiterLock.RLock()
	defer u.limiterLock.RUnlock()

	if u.sendLimiter != nil {
		send = int(u.sendLimiter.Limit())
	}
	if u.recvLimiter != nil {
		recv = int(u.recvLimiter.Limit())
	}
	return
}

func (u *User) Hash() string {
	return u.hash
}

func (u *User) SetTraffic(send, recv uint64) {
	u.trafficLock.Lock()
	atomic.StoreUint64(&u.sent, send)
	atomic.StoreUint64(&u.recv, recv)
	u.trafficLock.Unlock()
}

func (u *User) GetTraffic() (uint64, uint64) {
	return atomic.LoadUint64(&u.sent), atomic.LoadUint64(&u.recv)
}

func (u *User) ResetTraffic() (uint64, uint64) {
	sent, recv, _ := u.TakeTraffic(nil)
	return sent, recv
}

// TakeTraffic runs checkpoint while traffic mutation is blocked, then clears
// exactly the counters represented by that durable checkpoint. If checkpoint
// fails, the counters remain untouched.
func (u *User) TakeTraffic(checkpoint func(sent, recv uint64) error) (uint64, uint64, error) {
	u.trafficLock.Lock()
	defer u.trafficLock.Unlock()
	sent := atomic.LoadUint64(&u.sent)
	recv := atomic.LoadUint64(&u.recv)
	if sent == 0 && recv == 0 {
		return 0, 0, nil
	}
	if checkpoint != nil {
		if err := checkpoint(sent, recv); err != nil {
			return sent, recv, err
		}
	}
	atomic.StoreUint64(&u.sent, 0)
	atomic.StoreUint64(&u.recv, 0)
	atomic.StoreUint64(&u.lastSent, 0)
	atomic.StoreUint64(&u.lastRecv, 0)
	return sent, recv, nil
}

func (u *User) speedUpdater() {
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
			sent, recv := u.GetTraffic()
			lastSent := atomic.LoadUint64(&u.lastSent)
			lastRecv := atomic.LoadUint64(&u.lastRecv)
			var sendSpeed, recvSpeed uint64
			if sent >= lastSent {
				sendSpeed = sent - lastSent
			}
			if recv >= lastRecv {
				recvSpeed = recv - lastRecv
			}
			atomic.StoreUint64(&u.sendSpeed, sendSpeed)
			atomic.StoreUint64(&u.recvSpeed, recvSpeed)
			atomic.StoreUint64(&u.lastSent, sent)
			atomic.StoreUint64(&u.lastRecv, recv)
		}
	}
}

func (u *User) GetSpeed() (uint64, uint64) {
	return atomic.LoadUint64(&u.sendSpeed), atomic.LoadUint64(&u.recvSpeed)
}

type Authenticator struct {
	users sync.Map
	ctx   context.Context
}

func (a *Authenticator) AuthUser(hash string) (bool, statistic.User) {
	if user, found := a.users.Load(hash); found {
		return true, user.(*User)
	}
	return false, nil
}

func (a *Authenticator) AddUser(hash string) error {
	if _, found := a.users.Load(hash); found {
		return common.NewError("hash " + hash + " is already exist")
	}
	ctx, cancel := context.WithCancel(a.ctx)
	meter := &User{
		hash:    hash,
		ipTable: make(map[string]struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}
	go meter.speedUpdater()
	a.users.Store(hash, meter)
	return nil
}

func (a *Authenticator) DelUser(hash string) error {
	meter, found := a.users.Load(hash)
	if !found {
		return common.NewError("hash " + hash + " not found")
	}
	meter.(*User).Close()
	a.users.Delete(hash)
	return nil
}

func (a *Authenticator) ListUsers() []statistic.User {
	result := make([]statistic.User, 0)
	a.users.Range(func(k, v any) bool {
		result = append(result, v.(*User))
		return true
	})
	return result
}

func (a *Authenticator) Close() error {
	var firstErr error
	a.users.Range(func(key, value any) bool {
		if err := value.(*User).Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		a.users.Delete(key)
		return true
	})
	return firstErr
}

func NewAuthenticator(ctx context.Context) (statistic.Authenticator, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	u := &Authenticator{
		ctx: ctx,
	}
	for _, password := range cfg.Passwords {
		hash := common.SHA224String(password)
		u.AddUser(hash)
	}
	log.Debug("memory authenticator created")
	return u, nil
}

func init() {
	statistic.RegisterAuthenticatorCreator(Name, NewAuthenticator)
}
