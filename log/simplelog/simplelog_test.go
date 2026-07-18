package simplelog

import (
	"testing"

	"github.com/voidluo/trojan-go/log"
)

func TestSimpleLoggerLogLevelFilter(t *testing.T) {
	l := &SimpleLogger{}
	l.SetLogLevel(log.WarnLevel)

	// These should produce no output; at least they shouldn't panic
	l.Debug("should be silent")
	l.Debugf("should be silent %s", "too")
	l.Info("should be silent")
	l.Infof("should be silent %s", "too")
	l.Trace("should be silent")
	l.Tracef("should be silent %s", "too")

	// Warn and Error should not panic
	l.Warn("warning")
	l.Warnf("warning %s", "msg")
	l.Error("error")
	l.Errorf("error %s", "msg")
}

func TestSimpleLoggerAllLevel(t *testing.T) {
	l := &SimpleLogger{}
	l.SetLogLevel(log.AllLevel)

	l.Trace("trace")
	l.Tracef("trace %d", 1)
	l.Debug("debug")
	l.Debugf("debug %d", 2)
	l.Info("info")
	l.Infof("info %d", 3)
	l.Warn("warn")
	l.Warnf("warn %d", 4)
	l.Error("error")
	l.Errorf("error %d", 5)
}

func TestSimpleLoggerOffLevel(t *testing.T) {
	l := &SimpleLogger{}
	l.SetLogLevel(log.OffLevel)

	l.Error("should be silent")
	l.Warn("should be silent")
	l.Info("should be silent")
	l.Debug("should be silent")
	l.Trace("should be silent")
}

func TestSimpleLoggerSetOutput(t *testing.T) {
	l := &SimpleLogger{}
	l.SetOutput(nil)
}

func TestSimpleLoggerRegister(t *testing.T) {
	l := &SimpleLogger{}
	l.SetLogLevel(log.InfoLevel)
	l.Info("test after register")
}

func TestSimpleLoggerFormattedVariants(t *testing.T) {
	l := &SimpleLogger{}
	l.SetLogLevel(log.AllLevel)

	l.Errorf("error code: %d", 500)
	l.Warnf("warning at %s", "line 42")
	l.Infof("info: %v", []int{1, 2, 3})
	l.Debugf("debug value: %f", 3.14)
	l.Tracef("trace: %t", true)
}
