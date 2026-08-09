package repo

import (
	"context"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
)

// SetRoleDirect is a test helper that seeds a participant's role (and marks them
// a participant) without going through the authorized SetRole path.
func (m *MemStore) SetRoleDirect(meetingID, uid, role string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roles[key(meetingID, uid)] = role
	m.participants[key(meetingID, uid)] = true
}

// ParticipantRole implements Store.
func (m *MemStore) ParticipantRole(_ context.Context, meetingID, uid string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[meetingID]
	if ok && rec.HostUID == uid {
		return "H", true, nil
	}
	if r, ok := m.roles[key(meetingID, uid)]; ok {
		return r, true, nil
	}
	if m.participants[key(meetingID, uid)] {
		return "M", true, nil
	}
	return "", false, nil
}

func (m *MemStore) versioned(meetingID string, ifMatch int64) (*Meeting, error) {
	rec, ok := m.byID[meetingID]
	if !ok {
		return nil, ErrNotFound
	}
	if ifMatch != 0 && rec.Version != ifMatch {
		return nil, ErrVersionConflict
	}
	return rec, nil
}

// Transition implements Store.
func (m *MemStore) Transition(_ context.Context, meetingID string, to meeting.Status, _ string, ifMatch int64) (Meeting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.versioned(meetingID, ifMatch)
	if err != nil {
		return Meeting{}, err
	}
	if rec.Status == to {
		return *rec, nil // idempotent
	}
	if !meeting.CanTransition(rec.Status, to) {
		return Meeting{}, ErrInvalidTransition
	}
	rec.Status = to
	rec.Version++
	return *rec, nil
}

// SetLock implements Store.
func (m *MemStore) SetLock(_ context.Context, meetingID string, locked bool, ifMatch int64) (Meeting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.versioned(meetingID, ifMatch)
	if err != nil {
		return Meeting{}, err
	}
	if rec.Locked != locked {
		rec.Locked = locked
		rec.Version++
	}
	return *rec, nil
}

// SetRole implements Store.
func (m *MemStore) SetRole(_ context.Context, meetingID, uid, role string, ifMatch int64) (Meeting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.versioned(meetingID, ifMatch)
	if err != nil {
		return Meeting{}, err
	}
	m.roles[key(meetingID, uid)] = role
	m.participants[key(meetingID, uid)] = true
	rec.Version++
	return *rec, nil
}

// Remove implements Store: version-checked terminal removal that bumps the
// meeting version.
func (m *MemStore) Remove(_ context.Context, meetingID, uid string, ifMatch int64) (Meeting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.versioned(meetingID, ifMatch)
	if err != nil {
		return Meeting{}, err
	}
	m.removed[key(meetingID, uid)] = true
	rec.Version++
	return *rec, nil
}

// AcquireShare implements Store: version-checked single-holder acquisition.
func (m *MemStore) AcquireShare(_ context.Context, meetingID, uid, _ string, ifMatch int64) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.versioned(meetingID, ifMatch)
	if err != nil {
		return "", false, err
	}
	if h, ok := m.shareHolder[meetingID]; ok && h != "" && h != uid {
		return h, false, nil
	}
	m.shareHolder[meetingID] = uid
	rec.Version++
	return uid, true, nil
}

// ReleaseShare implements Store: clears the slot only if the current holder
// still equals expectedHolder, under a version check.
func (m *MemStore) ReleaseShare(_ context.Context, meetingID, expectedHolder string, ifMatch int64) (Meeting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.versioned(meetingID, ifMatch)
	if err != nil {
		return Meeting{}, err
	}
	if m.shareHolder[meetingID] != expectedHolder {
		return Meeting{}, ErrVersionConflict // holder changed between check and update
	}
	delete(m.shareHolder, meetingID)
	rec.Version++
	return *rec, nil
}

// ShareHolder implements Store.
func (m *MemStore) ShareHolder(_ context.Context, meetingID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.shareHolder[meetingID], nil
}

// EditScheduled implements Store. Topic/duration are not part of the in-memory
// Meeting projection, so the mem store applies the time and password-enabled
// changes and always bumps the version; the MySQL store persists all fields.
func (m *MemStore) EditScheduled(_ context.Context, meetingID string, in EditInput, ifMatch int64) (Meeting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, err := m.versioned(meetingID, ifMatch)
	if err != nil {
		return Meeting{}, err
	}
	if rec.Status != meeting.StatusScheduled {
		return Meeting{}, ErrInvalidTransition
	}
	if in.ScheduledStart != nil {
		rec.ScheduledStartAt = in.ScheduledStart.UTC()
	}
	if in.Password != nil {
		rec.PasswordEnabled = !in.Password.Clear
	}
	rec.Version++
	return *rec, nil
}
