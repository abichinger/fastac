package util

import "testing"

func testCacheGet(t *testing.T, c *LRUCache, key string, value interface{}, ok bool) {
	v, o := c.Get(key)
	if v != value || o != ok {
		t.Errorf("Get(%s): (%s, %t) supposed to be (%s, %t)", key, v, o, value, ok)
	}
}

func testCachePut(t *testing.T, c *LRUCache, key string, value interface{}) {
	c.Put(key, value)
	v, o := c.Get(key)
	if v != value || o != true {
		t.Errorf("Put(%s, %s): didn't add value", key, value)
	}
}

func testCacheEqual(t *testing.T, c *LRUCache, values []int) {
	cacheValues := []int{}
	for _, v := range c.m {
		cacheValues = append(cacheValues, v.value.(int))
	}

	if SetEqualsInt(values, cacheValues) == false {
		t.Errorf("cache values: %d supposed to be %d", cacheValues, values)
	}
}

func TestLRUCache(t *testing.T) {
	cache := NewLRUCache(3)
	testCachePut(t, cache, "one", 1)
	testCachePut(t, cache, "two", 2)
	testCacheGet(t, cache, "one", 1, true)
	testCachePut(t, cache, "three", 3)
	testCachePut(t, cache, "four", 4)
	testCacheGet(t, cache, "two", nil, false)
	testCacheEqual(t, cache, []int{1, 3, 4})
}
