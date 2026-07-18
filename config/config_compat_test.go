package config

import (
	"testing"
)

func TestCompatConfigDataJSON(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"run-type"`, `"run_type"`},
		{`"log-level"`, `"log_level"`},
		{`"log-file"`, `"log_file"`},
		{`"local-addr"`, `"local_addr"`},
		{`"local-port"`, `"local_port"`},
		{`"remote-addr"`, `"remote_addr"`},
		{`"remote-port"`, `"remote_port"`},
		{`"disable-http-check"`, `"disable_http_check"`},
		{`"udp-timeout"`, `"udp_timeout"`},
	}

	for _, tt := range tests {
		data := []byte(`{` + tt.input + `: "test"}`)
		result := compatConfigData(data, true)
		resultStr := string(result)
		if !contains(resultStr, tt.want) {
			t.Errorf("JSON compat: %s should become %s, got %s", tt.input, tt.want, resultStr)
		}
	}
}

func TestCompatConfigDataYAML(t *testing.T) {
	tests := []string{
		"run-type",
		"log-level",
		"log-file",
		"local-addr",
		"local-port",
		"remote-addr",
		"remote-port",
		"disable-http-check",
		"udp-timeout",
	}

	for _, key := range tests {
		data := []byte(key + ": test\n")
		result := compatConfigData(data, false)
		resultStr := string(result)
		if contains(resultStr, key) {
			t.Errorf("YAML compat: %s should be converted, but still present in %s", key, resultStr)
		}
	}
}

func TestCompatConfigDataNoChange(t *testing.T) {
	// Fields that do not contain hyphens should remain unchanged
	data := []byte(`{"password": ["test123"]}`)
	result := compatConfigData(data, true)
	if string(result) != string(data) {
		t.Errorf("data with no hyphens should not change: got %q", string(result))
	}
}

func TestRegisterConfigCreator(t *testing.T) {
	RegisterConfigCreator("test_compat", func() any {
		return &TestStruct{}
	})

	// Should be registered under name + "_CONFIG"
	if _, ok := creators["test_compat_CONFIG"]; !ok {
		t.Error("config creator not found in map")
	}
}

func TestConfigCreatorDuplicate(t *testing.T) {
	RegisterConfigCreator("test_dup", func() any { return &TestStruct{} })
	RegisterConfigCreator("test_dup", func() any { return &struct{}{} })

	// Second registration overwrites first
	if creators["test_dup_CONFIG"] == nil {
		t.Error("duplicate registration failed")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchStr(s, sub)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
