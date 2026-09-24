// Package session keeps the ePDG session table: one entry per UE that has been
// authorised over SWu and, when applicable, has an S2b bearer towards the EPC.
package session

import (
	"sort"
	"sync"
	"time"
)

// Status is the lifecycle state of a session.
type Status string

const (
	// StatusPending means the UE has been authorised and the ePDG is waiting for
	// it to bring up IKEv2/IPsec, which is the normal SWu model.
	StatusPending Status = "pending"
	// StatusUp means the CHILD_SA and, if configured, the S2b bearer are up.
	StatusUp Status = "up"
	// StatusDown means the session was torn down.
	StatusDown Status = "down"
)

// Session is one ePDG session.
type Session struct {
	UEID      string    `json:"ue_id"`
	IMSI      string    `json:"imsi"`
	APN       string    `json:"apn"`
	Status    Status    `json:"status"`
	PDNType   string    `json:"pdn_type,omitempty"`
	UEAddress string    `json:"ue_address,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store is a concurrency safe session table.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	now      func() time.Time
}

// NewStore builds an empty session table.
func NewStore() *Store {
	return &Store{sessions: map[string]*Session{}, now: time.Now}
}

// Upsert inserts or replaces a session, preserving CreatedAt.
func (s *Store) Upsert(in *Session) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	if existing, ok := s.sessions[in.UEID]; ok {
		in.CreatedAt = existing.CreatedAt
	} else {
		in.CreatedAt = now
	}
	in.UpdatedAt = now
	stored := *in
	s.sessions[in.UEID] = &stored
	return &stored
}

// Get returns a session by UE identity.
func (s *Store) Get(ueID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	found, ok := s.sessions[ueID]
	if !ok {
		return nil, false
	}
	copied := *found
	return &copied, true
}

// SetStatus updates the status of an existing session.
func (s *Store) SetStatus(ueID string, status Status) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found, ok := s.sessions[ueID]
	if !ok {
		return nil, false
	}
	found.Status = status
	found.UpdatedAt = s.now().UTC()
	copied := *found
	return &copied, true
}

// Delete removes a session.
func (s *Store) Delete(ueID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, ueID)
}

// List returns every session ordered by creation time.
func (s *Store) List() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		copied := *sess
		out = append(out, &copied)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].UEID < out[j].UEID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Len returns the number of sessions.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
