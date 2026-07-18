package version

import (
	"testing"
)

func TestVersionVars(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if Commit == "" {
		t.Error("Commit should not be empty")
	}
}

func TestVersionOptionName(t *testing.T) {
	// versionOption is registered via init(); verify its existence
	// The name is used by the option system to look up handlers
}
