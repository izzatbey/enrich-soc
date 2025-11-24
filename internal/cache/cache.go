package cache

import (
	"sync"
	"time"
)

type EnrichCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]cacheEntry
}

type cacheEntry struct {
	Value     interface{} // MUST BE interface{}
	ExpiresAt time.Time
}

func NewEnrichCache(ttl time.Duration) *EnrichCache {
	return &EnrichCache{
		ttl:     ttl,
		entries: make(map[string]cacheEntry),
	}
}

func (c *EnrichCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = cacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

func (c *EnrichCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		// expired
		delete(c.entries, key)
		return nil, false
	}

	return entry.Value, true
}
