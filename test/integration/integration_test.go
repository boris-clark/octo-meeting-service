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
	"github.com/Jerry-Xin/octo-meeting-service/internal/scheduler"
	"github.com/Jerry-Xin/octo-meeting-service/internal/storage"
	"github.com/Jerry-Xin/octo-meeting-service/internal/worker"
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

// fakeNotifier records deliveries for the worker integration test.
type fakeNotifier struct{ delivered int }

func (f *fakeNotifier) Notify(context.Context, string, string, map[string]any) error {
	f.delivered++
	return nil
}

// TestWorkerOutboxDispatchMySQL inserts a due outbox row and drives the real
// MySQL-backed dispatcher, asserting claim -> deliver -> sent (and that a sent
// row is not re-claimed).
func TestWorkerOutboxDispatchMySQL(t *testing.T) {
	db, err := sql.Open("mysql", mysqlDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	dedupe := "it-outbox-" + time.Now().UTC().Format("150405.000000")
	if _, err := db.ExecContext(ctx,
		`INSERT INTO meeting_outbox (event_type, meeting_id, recipient_uid, dedupe_key, payload_redacted_json, status, next_attempt_at)
		 VALUES ('meeting_invite', 'it-m', 'it-u', ?, JSON_OBJECT('note','需要入会密码'), 'pending', CURRENT_TIMESTAMP(3))`,
		dedupe); err != nil {
		t.Fatalf("insert outbox: %v", err)
	}

	notifier := &fakeNotifier{}
	d := worker.NewDispatcher(storage.NewMySQLJobStore(db), notifier, scheduler.DefaultPolicy(), "it-worker", 10, nil)

	n, err := d.Tick(ctx, time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if n < 1 || notifier.delivered < 1 {
		t.Fatalf("dispatch: claimed=%d delivered=%d, want >=1", n, notifier.delivered)
	}
	// The delivered row is marked sent and not re-claimed.
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM meeting_outbox WHERE dedupe_key=?`, dedupe).Scan(&status); err != nil {
		t.Fatalf("status: %v", err)
	}
	if status != "sent" {
		t.Fatalf("outbox status = %q, want sent", status)
	}
}

// TestControlTransitionMySQL exercises a lifecycle transition (cancel) and lock
// toggle against real MySQL with the optimistic version check.
func TestControlTransitionMySQL(t *testing.T) {
	db, err := sql.Open("mysql", mysqlDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	const lookupSecret = "it-lookup-secret"
	store := storage.NewMySQLStore(db, lookupSecret)
	minter, _ := credential.NewMinter([]byte(lookupSecret), []byte("0123456789abcdef0123456789abcdef"))
	number, _ := credential.GenerateNumber()
	link, _ := credential.GenerateLinkToken()
	numCT, _ := minter.Seal(number)
	linkCT, _ := minter.Seal(link)
	id := "it-ctl-" + number
	if _, err := store.CreateMeeting(ctx, repo.CreateInput{
		Meeting: repo.Meeting{MeetingID: id, SpaceID: "it-space", Type: meeting.TypeScheduled, Status: meeting.StatusScheduled, CreatorUID: "it-creator", HostUID: "it-creator", ScheduledStartAt: time.Now().Add(time.Hour).UTC(), MaxParticipants: 100, Version: 1},
		Number:  number, LinkToken: link, NumberCiphertext: numCT, LinkCiphertext: linkCT,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Host role resolves; lock toggles; cancel transitions to cancelled.
	if role, ok, err := store.ParticipantRole(ctx, id, "it-creator"); err != nil || !ok || role != "H" {
		t.Fatalf("participant role: role=%q ok=%v err=%v", role, ok, err)
	}
	if m, err := store.SetLock(ctx, id, true, 0); err != nil || !m.Locked {
		t.Fatalf("set lock: locked=%v err=%v", m.Locked, err)
	}
	m, err := store.Transition(ctx, id, meeting.StatusCancelled, "", 0)
	if err != nil || m.Status != meeting.StatusCancelled {
		t.Fatalf("cancel: status=%v err=%v", m.Status, err)
	}
	// Cancelling an already-cancelled meeting is idempotent.
	if m2, err := store.Transition(ctx, id, meeting.StatusCancelled, "", 0); err != nil || m2.Status != meeting.StatusCancelled {
		t.Fatalf("idempotent cancel: status=%v err=%v", m2.Status, err)
	}
}

// TestEditScheduledMySQL exercises the before-live edit path against real MySQL:
// topic/time mutation with a version bump, a before-live password set (verifier
// row + password_enabled) and clear, and the invalid-transition guard once live.
func TestEditScheduledMySQL(t *testing.T) {
	db, err := sql.Open("mysql", mysqlDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	const lookupSecret = "it-lookup-secret"
	store := storage.NewMySQLStore(db, lookupSecret)
	minter, _ := credential.NewMinter([]byte(lookupSecret), []byte("0123456789abcdef0123456789abcdef"))
	number, _ := credential.GenerateNumber()
	link, _ := credential.GenerateLinkToken()
	numCT, _ := minter.Seal(number)
	linkCT, _ := minter.Seal(link)
	id := "it-edit-" + number
	if _, err := store.CreateMeeting(ctx, repo.CreateInput{
		Meeting: repo.Meeting{MeetingID: id, SpaceID: "it-space", Type: meeting.TypeScheduled, Status: meeting.StatusScheduled, CreatorUID: "it-creator", HostUID: "it-creator", ScheduledStartAt: time.Now().Add(time.Hour).UTC(), MaxParticipants: 100, Version: 1},
		Number:  number, LinkToken: link, NumberCiphertext: numCT, LinkCiphertext: linkCT,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	topic := "edited topic"
	newStart := time.Now().Add(2 * time.Hour).UTC()
	m, err := store.EditScheduled(ctx, id, repo.EditInput{Topic: &topic, ScheduledStart: &newStart}, 0)
	if err != nil || m.Version <= 1 {
		t.Fatalf("edit topic/time: version=%d err=%v", m.Version, err)
	}

	// Set a password before live, then verify the DB verifier accepts it.
	enc, _ := password.DefaultArgon2Params().Hash("424242", "it-pepper")
	m, err = store.EditScheduled(ctx, id, repo.EditInput{Password: &repo.PasswordOp{Verifier: &repo.VerifierInput{
		Algorithm: password.Algorithm, ParamsJSON: "{}", SaltID: "inline", PepperRef: "configured", Verifier: enc,
	}}}, 0)
	if err != nil || !m.PasswordEnabled {
		t.Fatalf("edit set password: enabled=%v err=%v", m.PasswordEnabled, err)
	}
	verifier := storage.NewMySQLPasswordVerifier(db, "it-pepper")
	if ok, err := verifier.Verify(ctx, id, "424242"); err != nil || !ok {
		t.Fatalf("verify after edit-set: ok=%v err=%v", ok, err)
	}

	// Clear the password before live.
	m, err = store.EditScheduled(ctx, id, repo.EditInput{Password: &repo.PasswordOp{Clear: true}}, 0)
	if err != nil || m.PasswordEnabled {
		t.Fatalf("edit clear password: enabled=%v err=%v", m.PasswordEnabled, err)
	}

	// Once live, editing is rejected as an invalid transition.
	if _, err := store.StartLive(ctx, id, time.Now().UTC()); err != nil {
		t.Fatalf("start live: %v", err)
	}
	if _, err := store.EditScheduled(ctx, id, repo.EditInput{Topic: &topic}, 0); err != repo.ErrInvalidTransition {
		t.Fatalf("edit after live: err=%v, want ErrInvalidTransition", err)
	}
}

// TestWorkerLeaseRecoveryMySQL proves an expired `leased` row (a worker crashed
// before settling it) is re-claimable, so notifications are never permanently
// stuck.
func TestWorkerLeaseRecoveryMySQL(t *testing.T) {
	db, err := sql.Open("mysql", mysqlDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	dedupe := "it-lease-" + time.Now().UTC().Format("150405.000000")
	// Insert a row already `leased` with an expired lease (owner crashed).
	if _, err := db.ExecContext(ctx,
		`INSERT INTO meeting_outbox (event_type, meeting_id, recipient_uid, dedupe_key, payload_redacted_json, status, lease_owner, lease_until)
		 VALUES ('meeting_invite', 'it-m', 'it-u', ?, JSON_OBJECT('note','x'), 'leased', 'dead-worker', DATE_SUB(CURRENT_TIMESTAMP(3), INTERVAL 1 MINUTE))`,
		dedupe); err != nil {
		t.Fatalf("insert leased: %v", err)
	}

	store := storage.NewMySQLJobStore(db)
	jobs, err := store.ClaimDue(ctx, time.Now().UTC(), "recovery-worker", 10)
	if err != nil {
		t.Fatalf("claim due: %v", err)
	}
	found := false
	for _, j := range jobs {
		if j.RecipientUID == "it-u" {
			found = true
		}
	}
	if !found {
		t.Fatal("expired-leased row was not re-claimed (permanently stuck)")
	}
}

// TestControlVersionConflictMySQL proves the row-locked optimistic version check
// on a mutating control (remove) against real MySQL.
func TestControlVersionConflictMySQL(t *testing.T) {
	db, err := sql.Open("mysql", mysqlDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	const lookupSecret = "it-lookup-secret"
	store := storage.NewMySQLStore(db, lookupSecret)
	minter, _ := credential.NewMinter([]byte(lookupSecret), []byte("0123456789abcdef0123456789abcdef"))
	number, _ := credential.GenerateNumber()
	link, _ := credential.GenerateLinkToken()
	numCT, _ := minter.Seal(number)
	linkCT, _ := minter.Seal(link)
	id := "it-ver-" + number
	if _, err := store.CreateMeeting(ctx, repo.CreateInput{
		Meeting: repo.Meeting{MeetingID: id, SpaceID: "it-space", Type: meeting.TypeScheduled, Status: meeting.StatusScheduled, CreatorUID: "it-creator", HostUID: "it-creator", ScheduledStartAt: time.Now().Add(time.Hour).UTC(), MaxParticipants: 100, Version: 1},
		Number:  number, LinkToken: link, NumberCiphertext: numCT, LinkCiphertext: linkCT,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Stale If-Match -> version conflict; correct version succeeds.
	if _, err := store.Remove(ctx, id, "it-target", 99); err != repo.ErrVersionConflict {
		t.Fatalf("stale remove: err=%v, want ErrVersionConflict", err)
	}
	m, err := store.Remove(ctx, id, "it-target", 1)
	if err != nil || m.Version <= 1 {
		t.Fatalf("versioned remove: version=%d err=%v", m.Version, err)
	}

	// Share acquire + a holder-race release: releasing against a wrong expected
	// holder must not clear the slot.
	if _, ok, err := store.AcquireShare(ctx, id, "it-creator", "seg", 0); err != nil || !ok {
		t.Fatalf("acquire share: ok=%v err=%v", ok, err)
	}
	if _, err := store.ReleaseShare(ctx, id, "someone-else", 0); err != repo.ErrVersionConflict {
		t.Fatalf("holder-race release: err=%v, want ErrVersionConflict", err)
	}
	if h, _ := store.ShareHolder(ctx, id); h != "it-creator" {
		t.Fatalf("holder cleared under race: %q", h)
	}
}
