package geodata

import (
	"testing"
)

func TestNewGeodataLoader(t *testing.T) {
	loader := NewGeodataLoader()
	if loader == nil {
		t.Fatal("NewGeodataLoader returned nil")
	}
}

func TestGeodataLoaderInterface(t *testing.T) {
	var loader GeodataLoader = NewGeodataLoader()
	// Verify interface implementation
	_ = loader
}

func TestGeodataCacheType(t *testing.T) {
	cache := NewGeodataLoader()
	if _, ok := cache.(*geodataCache); !ok {
		t.Error("NewGeodataLoader should return *geodataCache")
	}
}
