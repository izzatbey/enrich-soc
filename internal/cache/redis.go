package cache

import (
    "context"
    "time"
    "github.com/redis/go-redis/v9"
)

type RedisCache struct {
    client *redis.Client
    ttl    time.Duration
}

func NewRedisCache(addr, pass string, db int, ttl time.Duration) *RedisCache {
    rdb := redis.NewClient(&redis.Options{
        Addr:     addr,
        Password: pass,
        DB:       db,
        PoolSize: 50,
        MinIdleConns: 10,
    })

    return &RedisCache{
        client: rdb,
        ttl:    ttl,
    }
}

func (r *RedisCache) Set(key, value string) {
    r.client.Set(context.Background(), key, value, r.ttl)
}

func (r *RedisCache) SetWithTTL(key, value string, ttl time.Duration) {
    r.client.Set(context.Background(), key, value, ttl)
}

func (r *RedisCache) Get(key string) (string, bool) {
    v, err := r.client.Get(context.Background(), key).Result()
    if err != nil {
        return "", false
    }
    return v, true
}

