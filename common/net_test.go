package common

import (
	"bytes"
	"testing"
)

func TestHumanFriendlyTraffic(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1024 B"}, // <= KiB stays in B
		{1025, "1.00 KiB"},
		{1536, "1.50 KiB"},
		{1048576, "1024.00 KiB"}, // <= MiB stays in KiB
		{1048577, "1.00 MiB"},
		{1073741824, "1024.00 MiB"}, // <= GiB stays in MiB
		{1073741825, "1.00 GiB"},
	}

	for _, tt := range tests {
		result := HumanFriendlyTraffic(tt.bytes)
		if result != tt.expected {
			t.Errorf("HumanFriendlyTraffic(%d) = %q, want %q", tt.bytes, result, tt.expected)
		}
	}
}

func TestWriteAllBytes(t *testing.T) {
	t.Run("write all", func(t *testing.T) {
		var buf bytes.Buffer
		payload := []byte("hello world")
		err := WriteAllBytes(&buf, payload)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), payload) {
			t.Fatalf("got %q, want %q", buf.Bytes(), payload)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteAllBytes(&buf, nil)
		if err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Fatal("expected empty buffer")
		}
	})
}
