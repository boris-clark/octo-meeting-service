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

// Remove implements Store.
func (m *MemStore) Remove(_ context.Context, meetingID, uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed[key(meetingID, uid)] = true
	return nil
}

// AcquireShare implements Store.
func (m *MemStore) AcquireShare(_ context.Context, meetingID, uid, _ string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.shareHolder[meetingID]; ok && h != "" && h != uid {
		return h, false, nil
	}
	m.shareHolder[meetingID] = uid
	return uid, true, nil
}

// ReleaseShare implements Store.
func (m *MemStore) ReleaseShare(_ context.Context, meetingID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.shareHolder, meetingID)
	return nil
}

// ShareHolder implements Store.
func (m *MemStore) ShareHolder(_ context.Context, meetingID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.shareHolder[meetingID], nil
}
