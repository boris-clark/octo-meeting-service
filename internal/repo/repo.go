// Package repo defines the persistence seams the admission and lifecycle handlers
// depend on, plus in-memory implementations used by unit/handler tests. The
// MySQL-backed implementations (transactional lifecycle over the schema in
// migrations/) plug in behind the same interfaces; keeping the interface small
// and storage-agnostic lets the domain logic be exercised without a live
// database. Lookups are by opaque credential material only.
package repo

import (
	"context"
	"sync"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
)

// Meeting is the authoritative meeting record (subset needed for admission and
// lifecycle transitions).
type Meeting struct {
	MeetingID        string
	SpaceID          string
	Type             meeting.Type
	Status           meeting.Status
	CreatorUID       string
	HostUID          string
	ScheduledStartAt time.Time
	PasswordEnabled  bool
	Locked           bool
	MaxParticipants  int
	ActualStartAt    time.Time
	Version          int64
}

// CredentialKind identifies how a caller referenced a meeting.
type CredentialKind string

// Credential kinds accepted by evaluate.
const (
	ByID     CredentialKind = "meeting_id"
	ByNumber CredentialKind = "meeting_number"
	ByLink   CredentialKind = "link_token"
)

// Store is the meeting persistence seam.
type Store interface {
	// Resolve looks up a meeting by one credential. found=false means no such
	// meeting (indistinguishable-404 territory).
	Resolve(ctx context.Context, kind CredentialKind, value string) (Meeting, bool, error)
	// ActiveParticipantCount returns the count of active (not left/superseded/
	// removed) participants, authoritative for the full check.
	ActiveParticipantCount(ctx context.Context, meetingID string) (int, error)
	// IsRemoved reports a terminal removal record for the caller.
	IsRemoved(ctx context.Context, meetingID, uid string) (bool, error)
	// IsInvitee / IsParticipant establish S-1 authorization-to-know.
	IsInvitee(ctx context.Context, meetingID, uid string) (bool, error)
	IsParticipant(ctx context.Context, meetingID, uid string) (bool, error)
	// StartLive atomically transitions a scheduled meeting to live on first
	// finalize, setting actual_start_at. It returns the updated record. It is a
	// no-op returning the current record when already live.
	StartLive(ctx context.Context, meetingID string, now time.Time) (Meeting, error)
	// CreateMeeting persists a new meeting with its credential (and optional
	// password verifier) under an idempotency guard. A duplicate idempotency key
	// with the same payload returns the first result (CreateResult.Replayed=true)
	// carrying the ORIGINAL persisted credential ciphertexts; a duplicate key
	// with a different payload returns ErrIdempotencyConflict.
	CreateMeeting(ctx context.Context, in CreateInput) (CreateResult, error)

	// ParticipantRole returns the actor's control role for a meeting: "H" for the
	// host, otherwise the participant's role. isParticipant is false when the
	// actor is neither host nor a participant.
	ParticipantRole(ctx context.Context, meetingID, uid string) (role string, isParticipant bool, err error)
	// Transition atomically applies a status transition (cancel -> cancelled,
	// end -> ended) under an optimistic version check. It is idempotent when the
	// meeting is already in the target terminal state. ErrVersionConflict on a
	// stale ifMatch (0 = no check); ErrInvalidTransition on an illegal move.
	Transition(ctx context.Context, meetingID string, to meeting.Status, endReason string, ifMatch int64) (Meeting, error)
	// SetLock toggles the meeting lock under an optimistic version check.
	SetLock(ctx context.Context, meetingID string, locked bool, ifMatch int64) (Meeting, error)
	// SetRole assigns a participant's role (H only, per the authz matrix).
	SetRole(ctx context.Context, meetingID, uid, role string, ifMatch int64) (Meeting, error)
	// Remove writes a terminal removal record that blocks future admission.
	Remove(ctx context.Context, meetingID, uid string) error
	// AcquireShare takes the single share-holder slot; ok=false and the current
	// holder are returned on conflict.
	AcquireShare(ctx context.Context, meetingID, uid, segmentID string) (holder string, ok bool, err error)
	// ShareHolder returns the current share-holder uid ("" if none).
	ShareHolder(ctx context.Context, meetingID string) (string, error)
	// ReleaseShare clears the share-holder slot (idempotent).
	ReleaseShare(ctx context.Context, meetingID string) error
}

// CreateResult is the outcome of CreateMeeting. On a replay it carries the
// original persisted credential ciphertexts (not freshly-minted values) so the
// handler can echo credentials that actually resolve.
type CreateResult struct {
	Meeting          Meeting
	Replayed         bool
	NumberCiphertext []byte
	LinkCiphertext   []byte
}

// MemStore is an in-memory Store for tests.
type MemStore struct {
	mu           sync.Mutex
	byID         map[string]*Meeting
	byNumber     map[string]string // number -> meeting_id
	byLink       map[string]string // link -> meeting_id
	removed      map[string]bool   // meetingID|uid
	invitees     map[string]bool
	participants map[string]bool
	activeCount  map[string]int
	idem         map[string]idemRecord
	creds        map[string]storedCreds
	roles        map[string]string // meetingID|uid -> role
	shareHolder  map[string]string // meetingID -> uid
}

type idemRecord struct {
	meetingID   string
	fingerprint string
}

// storedCreds holds the original credential ciphertexts for replay.
type storedCreds struct {
	numberCT []byte
	linkCT   []byte
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		byID:         map[string]*Meeting{},
		byNumber:     map[string]string{},
		byLink:       map[string]string{},
		removed:      map[string]bool{},
		invitees:     map[string]bool{},
		participants: map[string]bool{},
		activeCount:  map[string]int{},
		idem:         map[string]idemRecord{},
		creds:        map[string]storedCreds{},
		roles:        map[string]string{},
		shareHolder:  map[string]string{},
	}
}

func key(a, b string) string { return a + "|" + b }

// AddMeeting registers a meeting with optional number/link lookups.
func (m *MemStore) AddMeeting(rec Meeting, number, link string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := rec
	m.byID[rec.MeetingID] = &cp
	if number != "" {
		m.byNumber[number] = rec.MeetingID
	}
	if link != "" {
		m.byLink[link] = rec.MeetingID
	}
}

// SetRemoved marks a caller removed.
func (m *MemStore) SetRemoved(meetingID, uid string) { m.set(m.removed, meetingID, uid) }

// SetInvitee marks a caller invited.
func (m *MemStore) SetInvitee(meetingID, uid string) { m.set(m.invitees, meetingID, uid) }

// SetParticipant marks a caller an existing participant.
func (m *MemStore) SetParticipant(meetingID, uid string) { m.set(m.participants, meetingID, uid) }

// SetActiveCount sets the active participant count.
func (m *MemStore) SetActiveCount(meetingID string, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeCount[meetingID] = n
}

func (m *MemStore) set(set map[string]bool, meetingID, uid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set[key(meetingID, uid)] = true
}

// Resolve implements Store.
func (m *MemStore) Resolve(_ context.Context, kind CredentialKind, value string) (Meeting, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var id string
	switch kind {
	case ByID:
		id = value
	case ByNumber:
		id = m.byNumber[value]
	case ByLink:
		id = m.byLink[value]
	}
	rec, ok := m.byID[id]
	if !ok {
		return Meeting{}, false, nil
	}
	return *rec, true, nil
}

// ActiveParticipantCount implements Store.
func (m *MemStore) ActiveParticipantCount(_ context.Context, meetingID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeCount[meetingID], nil
}

// IsRemoved implements Store.
func (m *MemStore) IsRemoved(_ context.Context, meetingID, uid string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removed[key(meetingID, uid)], nil
}

// IsInvitee implements Store.
func (m *MemStore) IsInvitee(_ context.Context, meetingID, uid string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.invitees[key(meetingID, uid)], nil
}

// IsParticipant implements Store.
func (m *MemStore) IsParticipant(_ context.Context, meetingID, uid string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.participants[key(meetingID, uid)], nil
}

// StartLive implements Store.
func (m *MemStore) StartLive(_ context.Context, meetingID string, now time.Time) (Meeting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[meetingID]
	if !ok {
		return Meeting{}, ErrNotFound
	}
	if rec.Status == meeting.StatusScheduled {
		rec.Status = meeting.StatusLive
		rec.ActualStartAt = now
		rec.Version++
	}
	return *rec, nil
}

// VerifierInput carries the columns for a meeting_password_verifier row. The
// Verifier field is the non-reversible encoded verifier (e.g. Argon2id PHC);
// no raw password is ever included.
type VerifierInput struct {
	Algorithm  string
	ParamsJSON string
	SaltID     string
	PepperRef  string
	Verifier   string
}

// CreateInput is the payload for CreateMeeting. Number and LinkToken are the raw
// credentials; the store derives their lookup hashes (so the hashing secret
// stays in the store, matching Resolve). The *Ciphertext fields hold the
// envelope-encrypted display material prepared by the caller.
type CreateInput struct {
	Meeting          Meeting
	Number           string
	LinkToken        string
	NumberCiphertext []byte
	LinkCiphertext   []byte
	Verifier         *VerifierInput

	IdempotencyScope   string
	IdempotencyKey     string
	PayloadFingerprint string
}

// CreateMeeting implements Store for the in-memory store.
func (m *MemStore) CreateMeeting(_ context.Context, in CreateInput) (CreateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if in.IdempotencyKey != "" {
		k := key(in.IdempotencyScope, in.IdempotencyKey)
		if rec, ok := m.idem[k]; ok {
			if rec.fingerprint != in.PayloadFingerprint {
				return CreateResult{}, ErrIdempotencyConflict
			}
			existing := m.byID[rec.meetingID]
			orig := m.creds[rec.meetingID]
			// Return the ORIGINAL persisted credential ciphertexts on replay.
			return CreateResult{Meeting: *existing, Replayed: true, NumberCiphertext: orig.numberCT, LinkCiphertext: orig.linkCT}, nil
		}
		m.idem[k] = idemRecord{meetingID: in.Meeting.MeetingID, fingerprint: in.PayloadFingerprint}
	}

	cp := in.Meeting
	m.byID[cp.MeetingID] = &cp
	if in.Number != "" {
		m.byNumber[in.Number] = cp.MeetingID
	}
	if in.LinkToken != "" {
		m.byLink[in.LinkToken] = cp.MeetingID
	}
	m.creds[cp.MeetingID] = storedCreds{numberCT: in.NumberCiphertext, linkCT: in.LinkCiphertext}
	return CreateResult{Meeting: cp, Replayed: false, NumberCiphertext: in.NumberCiphertext, LinkCiphertext: in.LinkCiphertext}, nil
}
