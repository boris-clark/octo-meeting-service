//go:build integration

// Package integration holds end-to-end tests that require live MySQL and Redis.
// They are gated behind the `integration` build tag so the default CI (which has
// no datastores) never runs them; `make integration` brings up the compose
// stack, applies migrations, and runs them. Each test skips if its backing DSN
// is not provided, so the file still compiles and is a no-op without infra.
package integration

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"

	"github.com/Jerry-Xin/octo-meeting-service/internal/credential"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
	"github.com/Jerry-Xin/octo-meeting-service/internal/storage"
)

func mysqlDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("MEETING_IT_MYSQL_DSN")
	if dsn == "" {
		t.Skip("MEETING_IT_MYSQL_DSN not set; skipping MySQL integration test")
	}
	return dsn
}

func redisAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("MEETING_IT_REDIS_ADDR")
	if addr == "" {
		t.Skip("MEETING_IT_REDIS_ADDR not set; skipping Redis integration test")
	}
	return addr
}

// TestCreateResolveStartLiveMySQL exercises the create -> resolve (by number and
// link) -> start-live vertical against real MySQL, proving the credential-join
// queries execute (no ambiguous-column error) and the transaction commits.
func TestCreateResolveStartLiveMySQL(t *testing.T) {
	db, err := sql.Open("mysql", mysqlDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	const lookupSecret = "it-lookup-secret"
	store := storage.NewMySQLStore(db, lookupSecret)
	minter, err := credential.NewMinter([]byte(lookupSecret), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	number, _ := credential.GenerateNumber()
	link, _ := credential.GenerateLinkToken()
	numberCT, _ := minter.Seal(number)
	linkCT, _ := minter.Seal(link)
	id := "it-" + number

	enc, _ := password.DefaultArgon2Params().Hash("424242", "it-pepper")
	res, err := store.CreateMeeting(ctx, repo.CreateInput{
		Meeting: repo.Meeting{
			MeetingID: id, SpaceID: "it-space", Type: meeting.TypeScheduled,
			Status: meeting.StatusScheduled, CreatorUID: "it-creator", HostUID: "it-creator",
			ScheduledStartAt: time.Now().Add(time.Hour).UTC(), PasswordEnabled: true,
			MaxParticipants: 100, Version: 1,
		},
		Number: number, LinkToken: link, NumberCiphertext: numberCT, LinkCiphertext: linkCT,
		Verifier: &repo.VerifierInput{
			Algorithm: password.Algorithm, ParamsJSON: "{}", SaltID: "inline",
			PepperRef: "configured", Verifier: enc,
		},
		IdempotencyScope: "schedule", IdempotencyKey: "it-key-" + id, PayloadFingerprint: "fp1",
	})
	if err != nil || res.Replayed {
		t.Fatalf("CreateMeeting: replayed=%v err=%v", res.Replayed, err)
	}

	for _, tc := range []struct {
		kind  repo.CredentialKind
		value string
	}{{repo.ByID, id}, {repo.ByNumber, number}, {repo.ByLink, link}} {
		m, found, err := store.Resolve(ctx, tc.kind, tc.value)
		if err != nil || !found || m.MeetingID != id {
			t.Fatalf("Resolve(%s): found=%v err=%v id=%q", tc.kind, found, err, m.MeetingID)
		}
	}

	// Idempotent replay returns the first result AND the original persisted
	// credential ciphertext, which decrypts back to the original number.
	replay, err := store.CreateMeeting(ctx, repo.CreateInput{
		Meeting:          repo.Meeting{MeetingID: id + "-dup", SpaceID: "it-space", Type: meeting.TypeScheduled, Status: meeting.StatusScheduled, CreatorUID: "it-creator", HostUID: "it-creator", MaxParticipants: 100, Version: 1},
		Number:           number + "0",
		LinkToken:        link + "0",
		IdempotencyScope: "schedule", IdempotencyKey: "it-key-" + id, PayloadFingerprint: "fp1",
	})
	if err != nil || !replay.Replayed {
		t.Fatalf("replay: replayed=%v err=%v", replay.Replayed, err)
	}
	if replay.Meeting.MeetingID != id {
		t.Fatalf("replay returned wrong meeting: %q", replay.Meeting.MeetingID)
	}
	if gotNum, oerr := minter.Open(replay.NumberCiphertext); oerr != nil || gotNum != number {
		t.Fatalf("replay number: got %q err=%v, want original %q", gotNum, oerr, number)
	}

	// First finalize starts the meeting live.
	live, err := store.StartLive(ctx, id, time.Now().UTC())
	if err != nil || live.Status != meeting.StatusLive {
		t.Fatalf("StartLive: status=%v err=%v", live.Status, err)
	}

	// The DB-backed verifier accepts the password and rejects a wrong one.
	verifier := storage.NewMySQLPasswordVerifier(db, "it-pepper")
	if ok, err := verifier.Verify(ctx, id, "424242"); err != nil || !ok {
		t.Fatalf("verify correct: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifier.Verify(ctx, id, "000000"); ok {
		t.Fatal("verify wrong password returned true")
	}
}

// TestRedisStoresIntegration exercises the cooldown and pass-token hot paths
// against real Redis.
func TestRedisStoresIntegration(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: redisAddr(t)})
	defer func() { _ = client.Close() }()
	ctx := context.Background()
	now := time.Now().UTC()

	cd := storage.NewRedisCooldownStore(client, time.Minute)
	if err := cd.Put(ctx, "it-m", "it-u", password.State{Attempts: 2}); err != nil {
		t.Fatalf("cooldown put: %v", err)
	}
	if st, err := cd.Get(ctx, "it-m", "it-u"); err != nil || st.Attempts != 2 {
		t.Fatalf("cooldown get: %+v err=%v", st, err)
	}

	pt := storage.NewRedisPassTokenStore(client, time.Hour)
	token, err := pt.Issue(ctx, "it-m", "it-u", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if ok, _ := pt.Valid(ctx, token, "it-m", "it-u", now); !ok {
		t.Fatal("token should be valid")
	}
	if err := pt.Consume(ctx, token); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if ok, _ := pt.Valid(ctx, token, "it-m", "it-u", now); ok {
		t.Fatal("consumed token should be invalid")
	}
}
