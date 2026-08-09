package storage

import (
	"context"
	"testing"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

// compile-time: the Redis store satisfies the repo interface.
var _ repo.PassTokenStore = (*RedisPassTokenStore)(nil)

func TestRedisPassTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewRedisPassTokenStore(newTestRedis(t), time.Hour)
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	exp := now.Add(2 * time.Minute)

	token, err := store.Issue(ctx, "m1", "alice", exp)
	if err != nil || token == "" {
		t.Fatalf("Issue: token=%q err=%v", token, err)
	}

	// Valid for the right meeting+user before expiry.
	if ok, _ := store.Valid(ctx, token, "m1", "alice", now); !ok {
		t.Fatal("token should be valid before expiry")
	}
	// Bound to meeting and user.
	if ok, _ := store.Valid(ctx, token, "m2", "alice", now); ok {
		t.Fatal("token must be bound to its meeting")
	}
	if ok, _ := store.Valid(ctx, token, "m1", "bob", now); ok {
		t.Fatal("token must be bound to its user")
	}
	// Expired by the injected clock (independent of Redis TTL).
	if ok, _ := store.Valid(ctx, token, "m1", "alice", exp.Add(time.Nanosecond)); ok {
		t.Fatal("token must be invalid after expiry")
	}

	// ValidForUser tracks the marker.
	if ok, _ := store.ValidForUser(ctx, "m1", "alice", now); !ok {
		t.Fatal("ValidForUser should see the issued token")
	}
	if ok, _ := store.ValidForUser(ctx, "m1", "bob", now); ok {
		t.Fatal("ValidForUser must be per-user")
	}

	// Consume removes both the token and the marker.
	if err := store.Consume(ctx, token); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if ok, _ := store.Valid(ctx, token, "m1", "alice", now); ok {
		t.Fatal("consumed token must be invalid")
	}
	if ok, _ := store.ValidForUser(ctx, "m1", "alice", now); ok {
		t.Fatal("consumed token must clear the user marker")
	}
}

func TestRedisPassTokenMissing(t *testing.T) {
	store := NewRedisPassTokenStore(newTestRedis(t), time.Hour)
	now := time.Now()
	if ok, err := store.Valid(context.Background(), "nope", "m1", "alice", now); err != nil || ok {
		t.Fatalf("missing token: ok=%v err=%v", ok, err)
	}
	if ok, err := store.ValidForUser(context.Background(), "m1", "alice", now); err != nil || ok {
		t.Fatalf("missing user marker: ok=%v err=%v", ok, err)
	}
	// Consuming a missing token is a no-op.
	if err := store.Consume(context.Background(), "nope"); err != nil {
		t.Fatalf("Consume missing: %v", err)
	}
}

func TestRedisPassTokenReserveIsSingleFlight(t *testing.T) {
	ctx := context.Background()
	store := NewRedisPassTokenStore(newTestRedis(t), time.Hour)
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	token, err := store.Issue(ctx, "m1", "alice", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// First reserve wins.
	ok, reserved, err := store.Reserve(ctx, token, "m1", "alice", now)
	if err != nil || !ok || !reserved {
		t.Fatalf("first reserve: ok=%v reserved=%v err=%v, want true/true", ok, reserved, err)
	}
	// Concurrent second reserve is blocked (single-flight) while the first holds it.
	ok, reserved, err = store.Reserve(ctx, token, "m1", "alice", now)
	if err != nil || !ok || reserved {
		t.Fatalf("second reserve: ok=%v reserved=%v err=%v, want ok=true reserved=false", ok, reserved, err)
	}
	// Release lets a retry reserve again (LiveKit-failure retry path).
	if err := store.Release(ctx, token); err != nil {
		t.Fatalf("release: %v", err)
	}
	ok, reserved, err = store.Reserve(ctx, token, "m1", "alice", now)
	if err != nil || !ok || !reserved {
		t.Fatalf("reserve after release: ok=%v reserved=%v err=%v", ok, reserved, err)
	}
	// Commit consumes the token single-use.
	if err := store.Commit(ctx, token, "m1", "alice"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if v, _ := store.Valid(ctx, token, "m1", "alice", now); v {
		t.Fatal("committed token must be invalid")
	}
	if ok, _, _ := store.Reserve(ctx, token, "m1", "alice", now); ok {
		t.Fatal("reserve after commit must report ok=false (token gone)")
	}
	if vu, _ := store.ValidForUser(ctx, "m1", "alice", now); vu {
		t.Fatal("commit must clear the user marker")
	}
}

func TestRedisPassTokenReserveRejectsInvalid(t *testing.T) {
	ctx := context.Background()
	store := NewRedisPassTokenStore(newTestRedis(t), time.Hour)
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	token, _ := store.Issue(ctx, "m1", "alice", now.Add(time.Minute))

	// Unknown token, wrong meeting, wrong user, and expired all yield ok=false.
	if ok, _, _ := store.Reserve(ctx, "nope", "m1", "alice", now); ok {
		t.Fatal("unknown token must not reserve")
	}
	if ok, _, _ := store.Reserve(ctx, token, "other", "alice", now); ok {
		t.Fatal("wrong meeting must not reserve")
	}
	if ok, _, _ := store.Reserve(ctx, token, "m1", "bob", now); ok {
		t.Fatal("wrong user must not reserve")
	}
	if ok, _, _ := store.Reserve(ctx, token, "m1", "alice", now.Add(2*time.Minute)); ok {
		t.Fatal("expired token must not reserve")
	}
}
