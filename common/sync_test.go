package common

import (
	"sync"
	"testing"
	"time"
)

func TestNotifierSignalAndWait(t *testing.T) {
	n := NewNotifier()
	// Signal should not block
	n.Signal()

	// Wait should return a channel that receives the signal
	select {
	case <-n.Wait():
		// OK
	case <-time.After(time.Second):
		t.Fatal("Wait channel did not receive signal")
	}
}

func TestNotifierMultipleSignals(t *testing.T) {
	n := NewNotifier()
	// Multiple signals should not block (channel cap=1)
	for i := 0; i < 10; i++ {
		n.Signal()
	}

	// Consume one signal
	select {
	case <-n.Wait():
		// OK
	default:
		t.Fatal("expected signal on channel")
	}

	// After consuming, channel should be empty (cap 1 already consumed)
	select {
	case <-n.Wait():
		t.Fatal("unexpected second signal")
	default:
		// OK
	}
}

func TestNotifierConcurrent(t *testing.T) {
	n := NewNotifier()
	var wg sync.WaitGroup
	const producers = 5

	// Multiple concurrent producers signaling
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				n.Signal()
			}
		}()
	}
	wg.Wait()

	// At least one signal should be available
	select {
	case <-n.Wait():
		// OK
	case <-time.After(time.Second):
		t.Fatal("no signal received after concurrent signaling")
	}
}

func TestNotifierWaitReturnsOpenChannel(t *testing.T) {
	n := NewNotifier()
	ch := n.Wait()
	if ch == nil {
		t.Fatal("Wait() returned nil channel")
	}
}

func TestShutdownContext(t *testing.T) {
	ctx := ShutdownContext()
	if ctx == nil {
		t.Fatal("ShutdownContext returned nil")
	}

	// Context should not be done initially
	select {
	case <-ctx.Done():
		t.Fatal("shutdown context already done")
	default:
		// OK
	}

	SignalShutdown()

	// Context should be done after SignalShutdown
	select {
	case <-ctx.Done():
		// OK
	case <-time.After(time.Second):
		t.Fatal("shutdown context not done after SignalShutdown")
	}
}
