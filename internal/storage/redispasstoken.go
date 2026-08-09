package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisPassTokenStore is the durable, multi-instance-safe implementation of
// repo.PassTokenStore. A pass token is a Redis hash meeting:pass_token:{token}
// with fields meeting_id / uid / expires_at (unix millis). A per-user marker
// meeting:pass_user:{meetingID}:{uidHash} lets evaluate answer "does this user
// hold a valid pass" without scanning. Single-use is enforced atomically via a
// reservation (SET NX in a Lua script) taken before LiveKit mint; commit deletes
// the token, release clears only the reservation so a LiveKit failure can retry.
//
// Expiry is compared in milliseconds so the Lua tonumber() stays within float64
// precision (unix-nanos would exceed 2^53 and mis-compare).
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

func passTokenKey(token string) string   { return "meeting:pass_token:" + token }
func passReserveKey(token string) string { return "meeting:pass_reserve:" + token }

func passUserKey(meetingID, uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return fmt.Sprintf("meeting:pass_user:%s:%s", meetingID, hex.EncodeToString(sum[:8]))
}

// reserveScript atomically re-validates the token and takes a single-flight
// reservation. Returns {ok, reserved}: ok=0 => token invalid/expired;
// reserved=0 => another finalize already holds the reservation.
var reserveScript = redis.NewScript(`
local mid = redis.call('HGET', KEYS[1], 'meeting_id')
if not mid then return {0, 0} end
local uid = redis.call('HGET', KEYS[1], 'uid')
local exp = redis.call('HGET', KEYS[1], 'expires_at')
if mid ~= ARGV[1] or uid ~= ARGV[2] then return {0, 0} end
if tonumber(ARGV[3]) >= tonumber(exp) then return {0, 0} end
if redis.call('SET', KEYS[2], ARGV[4], 'NX', 'EX', tonumber(ARGV[5])) then
  return {1, 1}
end
return {1, 0}
`)

const reserveTTLSeconds = 30

// Issue mints a random token bound to meeting+user with the given expiry.
func (s *RedisPassTokenStore) Issue(ctx context.Context, meetingID, uid string, expiresAt time.Time) (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("redis pass token: random: %w", err)
	}
	token := hex.EncodeToString(buf)
	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, passTokenKey(token), map[string]any{
		"meeting_id": meetingID,
		"uid":        uid,
		"expires_at": expiresAt.UnixMilli(),
	})
	pipe.Expire(ctx, passTokenKey(token), s.maxTTL)
	pipe.Set(ctx, passUserKey(meetingID, uid), token, s.maxTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("redis pass token: issue: %w", err)
	}
	return token, nil
}

// Valid reports whether the token is bound to meeting+user and not expired at now.
func (s *RedisPassTokenStore) Valid(ctx context.Context, token, meetingID, uid string, now time.Time) (bool, error) {
	vals, err := s.client.HGetAll(ctx, passTokenKey(token)).Result()
	if err != nil {
		return false, fmt.Errorf("redis pass token: get: %w", err)
	}
	if len(vals) == 0 {
		return false, nil
	}
	exp, perr := parseMillis(vals["expires_at"])
	if perr != nil {
		return false, perr
	}
	return vals["meeting_id"] == meetingID && vals["uid"] == uid && now.UnixMilli() < exp, nil
}

// ValidForUser reports whether the user currently holds a valid pass, via the
// per-user marker.
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

// Reserve atomically re-validates the token and takes a single-flight
// reservation so only one finalize proceeds to LiveKit mint.
func (s *RedisPassTokenStore) Reserve(ctx context.Context, token, meetingID, uid string, now time.Time) (bool, bool, error) {
	owner := make([]byte, 8)
	if _, err := rand.Read(owner); err != nil {
		return false, false, fmt.Errorf("redis pass token: reserve owner: %w", err)
	}
	res, err := reserveScript.Run(ctx, s.client,
		[]string{passTokenKey(token), passReserveKey(token)},
		meetingID, uid, now.UnixMilli(), hex.EncodeToString(owner), reserveTTLSeconds).Result()
	if err != nil {
		return false, false, fmt.Errorf("redis pass token: reserve: %w", err)
	}
	arr, ok := res.([]any)
	if !ok || len(arr) != 2 {
		return false, false, fmt.Errorf("redis pass token: reserve: unexpected result %v", res)
	}
	return toInt64(arr[0]) == 1, toInt64(arr[1]) == 1, nil
}

// Commit deletes the token, its user marker, and the reservation (single-use).
func (s *RedisPassTokenStore) Commit(ctx context.Context, token, meetingID, uid string) error {
	pipe := s.client.TxPipeline()
	pipe.Del(ctx, passTokenKey(token))
	pipe.Del(ctx, passReserveKey(token))
	pipe.Del(ctx, passUserKey(meetingID, uid))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis pass token: commit: %w", err)
	}
	return nil
}

// Release clears only the reservation, leaving the token valid for retry.
func (s *RedisPassTokenStore) Release(ctx context.Context, token string) error {
	if err := s.client.Del(ctx, passReserveKey(token)).Err(); err != nil {
		return fmt.Errorf("redis pass token: release: %w", err)
	}
	return nil
}

// Consume deletes the token and its user marker given only the token (used
// outside the reserve/commit protocol). It looks up meeting/uid to clear the marker.
func (s *RedisPassTokenStore) Consume(ctx context.Context, token string) error {
	vals, err := s.client.HGetAll(ctx, passTokenKey(token)).Result()
	if err != nil {
		return fmt.Errorf("redis pass token: consume get: %w", err)
	}
	pipe := s.client.TxPipeline()
	pipe.Del(ctx, passTokenKey(token))
	pipe.Del(ctx, passReserveKey(token))
	if len(vals) > 0 {
		pipe.Del(ctx, passUserKey(vals["meeting_id"], vals["uid"]))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis pass token: consume: %w", err)
	}
	return nil
}

func parseMillis(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("redis pass token: empty expires_at")
	}
	var v int64
	if _, err := fmt.Sscan(s, &v); err != nil {
		return 0, fmt.Errorf("redis pass token: bad expires_at %q: %w", s, err)
	}
	return v, nil
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}
