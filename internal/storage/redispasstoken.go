package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisPassTokenStore is the durable, multi-instance-safe implementation of
// repo.PassTokenStore. A pass token is stored under meeting:pass_token:{token}
// with an authoritative expiry in the value (checked against the injected clock)
// and a per-user marker meeting:pass_user:{meetingID}:{uidHash} so evaluate can
// answer "does this user already hold a valid pass" without scanning. Redis TTL
// is a garbage-collection backstop; validity is decided by the stored expiry.
type RedisPassTokenStore struct {
	client redis.Cmdable
	maxTTL time.Duration
}

// NewRedisPassTokenStore builds the store. maxTTL bounds how long token keys
// linger in Redis regardless of their logical expiry.
func NewRedisPassTokenStore(client redis.Cmdable, maxTTL time.Duration) *RedisPassTokenStore {
	if maxTTL <= 0 {
		maxTTL = time.Hour
	}
	return &RedisPassTokenStore{client: client, maxTTL: maxTTL}
}

type passTokenValue struct {
	MeetingID string `json:"meeting_id"`
	UID       string `json:"uid"`
	ExpiresAt int64  `json:"expires_at"` // unix nanos
}

func passTokenKey(token string) string { return "meeting:pass_token:" + token }

func passUserKey(meetingID, uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return fmt.Sprintf("meeting:pass_user:%s:%s", meetingID, hex.EncodeToString(sum[:8]))
}

// Issue mints a random token bound to meeting+user with the given expiry.
func (s *RedisPassTokenStore) Issue(ctx context.Context, meetingID, uid string, expiresAt time.Time) (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("redis pass token: random: %w", err)
	}
	token := hex.EncodeToString(buf)
	val, err := json.Marshal(passTokenValue{MeetingID: meetingID, UID: uid, ExpiresAt: expiresAt.UnixNano()})
	if err != nil {
		return "", fmt.Errorf("redis pass token: marshal: %w", err)
	}
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, passTokenKey(token), val, s.maxTTL)
	pipe.Set(ctx, passUserKey(meetingID, uid), token, s.maxTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("redis pass token: issue: %w", err)
	}
	return token, nil
}

func (s *RedisPassTokenStore) load(ctx context.Context, token string) (passTokenValue, bool, error) {
	raw, err := s.client.Get(ctx, passTokenKey(token)).Result()
	if errors.Is(err, redis.Nil) {
		return passTokenValue{}, false, nil
	}
	if err != nil {
		return passTokenValue{}, false, fmt.Errorf("redis pass token: get: %w", err)
	}
	var v passTokenValue
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return passTokenValue{}, false, fmt.Errorf("redis pass token: unmarshal: %w", err)
	}
	return v, true, nil
}

// Valid reports whether the token is bound to meeting+user and not expired at now.
func (s *RedisPassTokenStore) Valid(ctx context.Context, token, meetingID, uid string, now time.Time) (bool, error) {
	v, ok, err := s.load(ctx, token)
	if err != nil || !ok {
		return false, err
	}
	return v.MeetingID == meetingID && v.UID == uid && now.UnixNano() < v.ExpiresAt, nil
}

// ValidForUser reports whether the user currently holds a valid pass for the
// meeting, via the per-user marker.
func (s *RedisPassTokenStore) ValidForUser(ctx context.Context, meetingID, uid string, now time.Time) (bool, error) {
	token, err := s.client.Get(ctx, passUserKey(meetingID, uid)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("redis pass token: user get: %w", err)
	}
	return s.Valid(ctx, token, meetingID, uid, now)
}

// Consume removes the token and its user marker (single-use on success).
func (s *RedisPassTokenStore) Consume(ctx context.Context, token string) error {
	v, ok, err := s.load(ctx, token)
	if err != nil {
		return err
	}
	pipe := s.client.TxPipeline()
	pipe.Del(ctx, passTokenKey(token))
	if ok {
		pipe.Del(ctx, passUserKey(v.MeetingID, v.UID))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis pass token: consume: %w", err)
	}
	return nil
}
