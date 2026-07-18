package geodata

import (
	"sync"
	"testing"
)

func TestGenericCacheSetAndGet(t *testing.T) {
	cache := &GenericCache[string]{}

	// Get on empty cache returns nil
	if got := cache.Get("key1"); got != nil {
		t.Error("expected nil for missing key")
	}

	// Set and Get
	val := "value1"
	cache.Set("key1", &val)
	got := cache.Get("key1")
	if got == nil || *got != "value1" {
		t.Errorf("got %v, want value1", got)
	}
}

func TestGenericCacheOverwrite(t *testing.T) {
	cache := &GenericCache[string]{}

	v1 := "first"
	cache.Set("key", &v1)

	v2 := "second"
	cache.Set("key", &v2)

	got := cache.Get("key")
	if got == nil || *got != "second" {
		t.Errorf("overwrite failed, got %v", got)
	}
}

func TestGenericCacheConcurrent(t *testing.T) {
	cache := &GenericCache[int]{}
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			val := n
			cache.Set("key", &val)
		}(i)
	}
	wg.Wait()

	// After concurrent writes, we should be able to read without panic
	got := cache.Get("key")
	if got != nil {
		t.Logf("concurrent Set result: %d", *got)
	}
}
