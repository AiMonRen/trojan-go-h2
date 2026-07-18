package common

import "context"

// globalShutdownCtx 全局优雅关闭上下文，供 main 信号处理与代理核心间协调退出
var globalShutdownCtx, globalShutdownCancel = context.WithCancel(context.Background())

// ShutdownContext 返回全局关闭 Context。代理核心等长生命周期组件可监听 Done() 实现优雅退出。
func ShutdownContext() context.Context {
	return globalShutdownCtx
}

// SignalShutdown 触发全局优雅关闭（由 main 信号处理调用）。
func SignalShutdown() {
	globalShutdownCancel()
}

// Notifier is a utility for notifying changes. The change producer may notify changes multiple time, and the consumer may get notified asynchronously.
type Notifier struct {
	c chan struct{}
}

// NewNotifier creates a new Notifier.
func NewNotifier() *Notifier {
	return &Notifier{
		c: make(chan struct{}, 1),
	}
}

// Signal signals a change, usually by producer. This method never blocks.
func (n *Notifier) Signal() {
	select {
	case n.c <- struct{}{}:
	default:
	}
}

// Wait returns a channel for waiting for changes. The returned channel never gets closed.
func (n *Notifier) Wait() <-chan struct{} {
	return n.c
}
