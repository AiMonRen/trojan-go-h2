package option

import (
	"testing"

	"github.com/voidluo/trojan-go/common"
)

type testHandler struct {
	name     string
	priority int
	handled  bool
}

func (h *testHandler) Name() string  { return h.name }
func (h *testHandler) Priority() int { return h.priority }
func (h *testHandler) Handle() error { h.handled = true; return nil }

func TestRegisterAndPopHandler(t *testing.T) {
	h := &testHandler{name: "test1", priority: 5}
	RegisterHandler(h)

	popped, err := PopOptionHandler()
	if err != nil {
		t.Fatal("PopOptionHandler:", err)
	}
	if popped.Name() != "test1" {
		t.Errorf("got %q, want test1", popped.Name())
	}
}

func TestPopHighestPriority(t *testing.T) {
	low := &testHandler{name: "low", priority: 1}
	mid := &testHandler{name: "mid", priority: 5}
	high := &testHandler{name: "high", priority: 10}

	RegisterHandler(low)
	RegisterHandler(mid)
	RegisterHandler(high)

	// Should pop highest priority first
	popped, err := PopOptionHandler()
	if err != nil {
		t.Fatal(err)
	}
	if popped.Name() != "high" {
		t.Errorf("expected 'high' first, got %q", popped.Name())
	}

	// Then mid
	popped, err = PopOptionHandler()
	if err != nil {
		t.Fatal(err)
	}
	if popped.Name() != "mid" {
		t.Errorf("expected 'mid' second, got %q", popped.Name())
	}

	// Then low
	popped, err = PopOptionHandler()
	if err != nil {
		t.Fatal(err)
	}
	if popped.Name() != "low" {
		t.Errorf("expected 'low' third, got %q", popped.Name())
	}
}

func TestPopFromEmpty(t *testing.T) {
	h := &testHandler{name: "tmp", priority: 1}
	RegisterHandler(h)

	// Pop the only handler
	PopOptionHandler()

	// Now empty
	_, err := PopOptionHandler()
	if err == nil {
		t.Fatal("expected error from empty handler map")
	}
}

func TestHandleCalled(t *testing.T) {
	h := &testHandler{name: "handle-test", priority: 1}
	RegisterHandler(h)

	popped, _ := PopOptionHandler()
	err := popped.Handle()
	if err != nil {
		t.Fatal(err)
	}
	if !h.handled {
		t.Fatal("Handle() was not called")
	}
}

func TestSamePriorityOrder(t *testing.T) {
	a := &testHandler{name: "a", priority: 1}
	b := &testHandler{name: "b", priority: 1}

	RegisterHandler(a)
	RegisterHandler(b)

	// With same priority, either can be popped first
	popped, err := PopOptionHandler()
	if err != nil {
		t.Fatal(err)
	}
	if popped.Name() != "a" && popped.Name() != "b" {
		t.Errorf("unexpected handler: %q", popped.Name())
	}

	// Second pop should get the other
	popped, err = PopOptionHandler()
	if err != nil {
		t.Fatal(err)
	}
}

func TestErrorReturnedFromHandle(t *testing.T) {
	h := &testHandler{name: "error-test", priority: 1}
	RegisterHandler(h)

	// Make sure the full flow works: register -> pop -> handle
	popped, err := PopOptionHandler()
	if err != nil {
		t.Fatal(err)
	}
	result := popped.Handle()
	if result != nil {
		t.Fatal("unexpected error from Handle:", result)
	}

	// Also test that an error-returning handler works
	errHandler := &errorHandler{name: "err", priority: 1}
	RegisterHandler(errHandler)
	popped, _ = PopOptionHandler()
	if result := popped.Handle(); result == nil {
		t.Fatal("expected error from Handle")
	}
}

type errorHandler struct {
	name     string
	priority int
}

func (h *errorHandler) Name() string  { return h.name }
func (h *errorHandler) Priority() int { return 1 }
func (h *errorHandler) Handle() error { return common.NewError("expected test error") }
