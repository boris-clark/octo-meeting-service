package storage

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

func meetingRow() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"meeting_id", "space_id", "type", "status", "creator_uid", "host_uid",
		"scheduled_start_at", "duration_minutes", "actual_start_at", "password_enabled",
		"locked", "max_participants", "version",
	}).AddRow("m1", "s1", "scheduled", "live", "creator", "host",
		nil, nil, nil, true, false, 100, int64(2))
}

func assertResolved(t *testing.T, m repo.Meeting, found bool, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if !found {
		t.Fatal("Resolve returned found=false, want true")
	}
	if m.MeetingID != "m1" || m.SpaceID != "s1" || m.Status != meeting.StatusLive || m.Version != 2 {
		t.Fatalf("unexpected meeting: %+v", m)
	}
	if !m.PasswordEnabled {
		t.Fatalf("password_enabled not scanned: %+v", m)
	}
}

// TestResolveByNumberQualifiesColumns is the regression guard for the ambiguous
// meeting_id blocker (XIN-1804). The expected-query regexp requires the SELECT
// list to be qualified (m.meeting_id ...) and to JOIN meeting_credential; the
// pre-fix unqualified list ("SELECT meeting_id, ...") does not match, so this
// test fails red before the fix and passes green after.
func TestResolveByNumberQualifiesColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	store := NewMySQLStore(db, "lookup-secret")
	// Match a qualified select joined to meeting_credential on number_lookup_hash.
	mock.ExpectQuery(`(?s)SELECT m\.meeting_id, m\.space_id.*m\.version\s+FROM meeting m\s+JOIN meeting_credential c.*number_lookup_hash`).
		WithArgs(store.lookupHash("135790")).
		WillReturnRows(meetingRow())

	m, found, err := store.Resolve(context.Background(), repo.ByNumber, "135790")
	assertResolved(t, m, found, err)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (query shape mismatch = the ambiguous-column bug): %v", err)
	}
}

func TestResolveByLinkQualifiesColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	store := NewMySQLStore(db, "lookup-secret")
	mock.ExpectQuery(`(?s)SELECT m\.meeting_id, m\.space_id.*m\.version\s+FROM meeting m\s+JOIN meeting_credential c.*link_token_lookup_hash`).
		WithArgs(store.lookupHash("link-abc")).
		WillReturnRows(meetingRow())

	m, found, err := store.Resolve(context.Background(), repo.ByLink, "link-abc")
	assertResolved(t, m, found, err)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestResolveByIDSingleTable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	store := NewMySQLStore(db, "")
	// The single-table ID lookup is unqualified and must not join.
	mock.ExpectQuery(`(?s)SELECT meeting_id, space_id.*FROM meeting WHERE meeting_id = \?`).
		WithArgs("m1").
		WillReturnRows(meetingRow())

	m, found, err := store.Resolve(context.Background(), repo.ByID, "m1")
	assertResolved(t, m, found, err)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestResolveNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	store := NewMySQLStore(db, "lookup-secret")
	// Empty result set -> found=false, no error (QueryRow.Scan -> ErrNoRows).
	mock.ExpectQuery(`JOIN meeting_credential`).
		WithArgs(store.lookupHash("000000")).
		WillReturnRows(sqlmock.NewRows([]string{"meeting_id"}))

	_, found, err := store.Resolve(context.Background(), repo.ByNumber, "000000")
	if err != nil {
		t.Fatalf("not-found should not error: %v", err)
	}
	if found {
		t.Fatal("expected found=false for empty result")
	}
}

func TestResolveByNumberDisabledWithoutSecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// No lookup secret configured: number/link resolution is disabled and must
	// NOT issue any query.
	store := NewMySQLStore(db, "")
	_, found, err := store.Resolve(context.Background(), repo.ByNumber, "135790")
	if err != nil || found {
		t.Fatalf("disabled number lookup: found=%v err=%v, want false/nil", found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no query should have been issued: %v", err)
	}
}
