package log

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// mockLogger captures log output for testing
type mockLogger struct {
	w *bytes.Buffer
}

func (m *mockLogger) Fatal(v ...any)             { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Fatalf(f string, v ...any)  { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Error(v ...any)             { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Errorf(f string, v ...any)  { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Warn(v ...any)              { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Warnf(f string, v ...any)   { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Info(v ...any)              { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Infof(f string, v ...any)   { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Debug(v ...any)             { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Debugf(f string, v ...any)  { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Trace(v ...any)             { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) Tracef(f string, v ...any)  { m.w.Write([]byte(v[0].(string))) }
func (m *mockLogger) SetLogLevel(level LogLevel) {}
func (m *mockLogger) SetOutput(w io.Writer)      {}

func TestLogLevelFiltering(t *testing.T) {
	l := &EmptyLogger{}
	l.SetLogLevel(InfoLevel)
	l.Debug("silent")
	l.Info("silent")
	l.Warn("silent")
	l.Error("silent")
}

func TestPackageLevelFunctions(t *testing.T) {
	original := logger
	defer func() { logger = original }()

	var buf bytes.Buffer
	mock := &mockLogger{w: &buf}
	RegisterLogger(mock)

	Info("test info")
	if !strings.Contains(buf.String(), "test info") {
		t.Errorf("expected 'test info', got %q", buf.String())
	}
	buf.Reset()

	Warn("test warn")
	if !strings.Contains(buf.String(), "test warn") {
		t.Errorf("expected 'test warn', got %q", buf.String())
	}
	buf.Reset()

	Error("test error")
	if !strings.Contains(buf.String(), "test error") {
		t.Errorf("expected 'test error', got %q", buf.String())
	}
	buf.Reset()

	Debug("test debug")
	if !strings.Contains(buf.String(), "test debug") {
		t.Errorf("expected 'test debug', got %q", buf.String())
	}
}

func TestRegisterLoggerFunc(t *testing.T) {
	original := logger
	defer func() { logger = original }()

	var buf bytes.Buffer
	mock := &mockLogger{w: &buf}
	RegisterLogger(mock)
	if logger != mock {
		t.Fatal("RegisterLogger did not set logger")
	}
}

func TestSetLogLevel(t *testing.T) {
	original := logger
	defer func() { logger = original }()

	l := &EmptyLogger{}
	RegisterLogger(l)
	SetLogLevel(WarnLevel)
}

func TestSetOutput(t *testing.T) {
	original := logger
	defer func() { logger = original }()

	l := &EmptyLogger{}
	RegisterLogger(l)
	SetOutput(nil)
}

func TestRegisterLoggerPropagation(t *testing.T) {
	original := logger
	defer func() { logger = original }()

	var buf bytes.Buffer
	mock := &mockLogger{w: &buf}
	RegisterLogger(mock)

	Debugf("test %s", "formatted")
	if !strings.Contains(buf.String(), "formatted") {
		t.Errorf("expected 'formatted', got %q", buf.String())
	}
}
