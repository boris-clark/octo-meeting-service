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
