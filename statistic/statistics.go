package statistic

import (
	"context"
	"io"
	"strings"
	"sync"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/log"
)

type TrafficMeter interface {
	io.Closer
	Hash() string
	AddTraffic(sent, recv int)
	AddTraffic64(sent, recv uint64)
	SubtractTraffic(sent, recv uint64)
	TakeTraffic(checkpoint func(sent, recv uint64) error) (sent, recv uint64, err error)
	GetTraffic() (sent, recv uint64)
	SetTraffic(sent, recv uint64)
	ResetTraffic() (sent, recv uint64)
	GetSpeed() (sent, recv uint64)
	GetSpeedLimit() (sent, recv int)
	SetSpeedLimit(sent, recv int)
}

type IPRecorder interface {
	AddIP(string) bool
	DelIP(string) bool
	GetIP() int
	SetIPLimit(int)
	GetIPLimit() int
}

type User interface {
	TrafficMeter
	IPRecorder
}

type Authenticator interface {
	io.Closer
	AuthUser(hash string) (valid bool, user User)
	AddUser(hash string) error
	DelUser(hash string) error
	ListUsers() []User
}

type Creator func(ctx context.Context) (Authenticator, error)

var (
	createdAuthLock sync.Mutex
	authCreators    = make(map[string]Creator)
	createdAuth     = make(map[context.Context]Authenticator)
)

func RegisterAuthenticatorCreator(name string, creator Creator) {
	createdAuthLock.Lock()
	defer createdAuthLock.Unlock()
	authCreators[strings.ToUpper(name)] = creator
}

func NewAuthenticator(ctx context.Context, name string) (Authenticator, error) {
	// allocate a unique authenticator for each context
	createdAuthLock.Lock() // avoid concurrent map read/write
	defer createdAuthLock.Unlock()
	if auth, found := createdAuth[ctx]; found {
		log.Debug("authenticator has been created:", name)
		return auth, nil
	}
	creator, found := authCreators[strings.ToUpper(name)]
	if !found {
		return nil, common.NewError("auth driver name " + name + " not found")
	}
	auth, err := creator(ctx)
	if err != nil {
		return nil, err
	}
	createdAuth[ctx] = auth
	return auth, err
}

// DeregisterAuthenticator 释放由指定 Context 注册的全局认证器引用，
// 避免 GC Root 强引用导致的内存泄漏。调用方应在 Context 生命周期结束时调用。
func DeregisterAuthenticator(ctx context.Context) {
	createdAuthLock.Lock()
	defer createdAuthLock.Unlock()
	delete(createdAuth, ctx)
}

// CloseAuthenticator removes and closes the authenticator owned by ctx.
// The external Close call happens after releasing the registry lock.
func CloseAuthenticator(ctx context.Context) error {
	createdAuthLock.Lock()
	auth := createdAuth[ctx]
	delete(createdAuth, ctx)
	createdAuthLock.Unlock()
	if auth == nil {
		return nil
	}
	return auth.Close()
}

// AuthenticatorCount reports the number of cached authenticators.
func AuthenticatorCount() int {
	createdAuthLock.Lock()
	defer createdAuthLock.Unlock()
	return len(createdAuth)
}
