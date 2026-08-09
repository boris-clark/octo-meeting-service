package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
)

// RedisCooldownStore is the Redis-backed password attempt/cooldown hot path
// (backend appendix §6/§9). State is stored under a meeting:pw_attempt:* hash
// with a TTL so stale counters expire. The uid is hashed into the key so no raw
// user id lands in Redis. The attempt/cooldown transition itself is computed by
// the shared, tested password.Policy — Redis holds the state, Go owns the rule.
type RedisCooldownStore struct {
	client redis.Cmdable
	ttl    time.Duration
}

// NewRedisCooldownStore builds a store. ttl bounds how long idle attempt state
// survives; it should exceed the cooldown duration.
func NewRedisCooldownStore(client redis.Cmdable, ttl time.Duration) *RedisCooldownStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &RedisCooldownStore{client: client, ttl: ttl}
}

func (s *RedisCooldownStore) key(meetingID, uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return fmt.Sprintf("meeting:pw_attempt:%s:%s", meetingID, hex.EncodeToString(sum[:8]))
}

// Get reads the current attempt state, returning the zero state when absent.
func (s *RedisCooldownStore) Get(ctx context.Context, meetingID, uid string) (password.State, error) {
	vals, err := s.client.HGetAll(ctx, s.key(meetingID, uid)).Result()
	if err != nil {
		return password.State{}, fmt.Errorf("redis cooldown get: %w", err)
	}
	var st password.State
	if a, ok := vals["attempts"]; ok {
		if n, err := strconv.Atoi(a); err == nil {
			st.Attempts = n
		}
	}
	if cu, ok := vals["cooldown_until"]; ok {
		if ns, err := strconv.ParseInt(cu, 10, 64); err == nil && ns > 0 {
			st.CooldownUntil = time.Unix(0, ns).UTC()
		}
	}
	return st, nil
}

// Put persists the attempt state and refreshes the TTL.
func (s *RedisCooldownStore) Put(ctx context.Context, meetingID, uid string, st password.State) error {
	key := s.key(meetingID, uid)
	var cooldownNanos int64
	if !st.CooldownUntil.IsZero() {
		cooldownNanos = st.CooldownUntil.UnixNano()
	}
	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{
		"attempts":       st.Attempts,
		"cooldown_until": cooldownNanos,
	})
	pipe.Expire(ctx, key, s.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis cooldown put: %w", err)
	}
	return nil
}
