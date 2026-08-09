package storage

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
)

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

func TestRedisCooldownRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := NewRedisCooldownStore(newTestRedis(t), 10*time.Minute)

	// Absent key -> zero state.
	st, err := store.Get(ctx, "m1", "alice")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if st.Attempts != 0 || !st.CooldownUntil.IsZero() {
		t.Fatalf("absent state not zero: %+v", st)
	}

	// Persist attempts + cooldown, read back.
	cooldown := time.Date(2026, 8, 9, 12, 5, 0, 0, time.UTC)
	if err := store.Put(ctx, "m1", "alice", password.State{Attempts: 5, CooldownUntil: cooldown}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.Get(ctx, "m1", "alice")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Attempts != 5 || !got.CooldownUntil.Equal(cooldown) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestRedisCooldownDrivesPolicy(t *testing.T) {
	ctx := context.Background()
	store := NewRedisCooldownStore(newTestRedis(t), 10*time.Minute)
	pol := password.DefaultPolicy()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	// Five wrong attempts persisted through Redis should reach cooldown, using
	// the shared policy for the transition.
	for i := 1; i <= 5; i++ {
		st, _ := store.Get(ctx, "m2", "bob")
		ns, out := pol.Verify(st, now, false)
		if err := store.Put(ctx, "m2", "bob", ns); err != nil {
			t.Fatalf("put: %v", err)
		}
		if i < 5 && out.Code != "MEETING_PASSWORD_INVALID" {
			t.Fatalf("attempt %d: %v", i, out.Code)
		}
		if i == 5 && out.Code != "MEETING_PASSWORD_COOLDOWN" {
			t.Fatalf("attempt 5 should cooldown: %v", out.Code)
		}
	}

	// Persisted cooldown blocks the next attempt without a verifier check.
	st, _ := store.Get(ctx, "m2", "bob")
	_, out := pol.Verify(st, now.Add(time.Minute), true)
	if out.Code != "MEETING_PASSWORD_COOLDOWN" {
		t.Fatalf("persisted cooldown not honored: %v", out.Code)
	}
}

func TestRedisCooldownKeyHashesUID(t *testing.T) {
	store := NewRedisCooldownStore(newTestRedis(t), time.Minute)
	if k := store.key("m1", "alice@example.com"); k == "meeting:pw_attempt:m1:alice@example.com" {
		t.Fatal("raw uid must not appear in the redis key")
	}
}
