package sloglog

import (
	"bytes"
	"strings"
	"testing"

	"github.com/voidluo/trojan-go/log"
)

func TestSlogLoggerNew(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)
	if l == nil {
		t.Fatal("NewLogger returned nil")
	}

	l.Info("hello world")

	output := buf.String()
	if !strings.Contains(output, "hello world") {
		t.Errorf("expected 'hello world' in output, got %q", output)
	}
}

func TestSlogLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	// Default level is Info, so Debug/Trace should be suppressed
	l.Debug("should not appear")
	l.Trace("should not appear")
	l.Info("should appear")

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Error("Debug/Trace should be suppressed at Info level")
	}
	if !strings.Contains(output, "should appear") {
		t.Error("Info should appear at Info level")
	}
}

func TestSlogLoggerSetLogLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	// Set to Warn level
	l.SetLogLevel(log.WarnLevel)

	l.Info("info suppressed")
	l.Debug("debug suppressed")
	l.Trace("trace suppressed")
	l.Warn("warn appears")

	output := buf.String()
	if strings.Contains(output, "info suppressed") || strings.Contains(output, "debug suppressed") {
		t.Error("Info/Debug should be suppressed at Warn level")
	}
	if !strings.Contains(output, "warn appears") {
		t.Error("Warn should appear at Warn level")
	}
}

func TestSlogLoggerAllLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)
	l.SetLogLevel(log.AllLevel)

	l.Trace("trace msg")
	l.Debug("debug msg")
	l.Info("info msg")
	l.Warn("warn msg")
	l.Error("error msg")

	output := buf.String()
	for _, word := range []string{"trace msg", "debug msg", "info msg", "warn msg", "error msg"} {
		if !strings.Contains(output, word) {
			t.Errorf("expected %q in output at AllLevel", word)
		}
	}
}

func TestSlogLoggerOffLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)
	l.SetLogLevel(log.OffLevel)

	l.Error("should be silent")
	l.Warn("should be silent")

	output := buf.String()
	if output != "" {
		t.Errorf("expected empty output at OffLevel, got %q", output)
	}
}

func TestSlogLoggerFormatted(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	l.Infof("value=%d name=%s", 42, "test")
	output := buf.String()
	if !strings.Contains(output, "value=42") || !strings.Contains(output, "name=test") {
		t.Errorf("expected formatted output, got %q", output)
	}
}

func TestSlogLoggerSetOutput(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	l := NewLogger(&buf1)

	l.Info("first")
	l.SetOutput(&buf2)
	l.Info("second")

	output1 := buf1.String()
	output2 := buf2.String()

	if !strings.Contains(output1, "first") {
		t.Error("first output not in buffer 1")
	}
	if !strings.Contains(output2, "second") {
		t.Error("second output not in buffer 2")
	}
}

func TestSlogLoggerFatalLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)
	l.SetLogLevel(log.FatalLevel)

	l.Error("error suppressed")
	l.Warn("warn suppressed")
	l.Info("info suppressed")

	output := buf.String()
	if output != "" {
		t.Errorf("expected no output at FatalLevel, got %q", output)
	}
}
