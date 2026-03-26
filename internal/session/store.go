package session

import (
	"sync"
	"time"
)

type Status string

const (
	StatusPending Status = "pending"
	StatusUp      Status = "up"
	StatusDown    Status = "down"
)

type Session struct {
	UEID      string    `json:"ue_id"`
	IMSI      string    `json:"imsi"`
	APN       string    `json:"apn"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewStore() *Store {
	return &Store{sessions: map[string]Session{}}
}

func (s *Store) Upsert(session Session) Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	old, ok := s.sessions[session.UEID]
	if !ok {
		session.CreatedAt = now
	} else {
		session.CreatedAt = old.CreatedAt
	}
	session.UpdatedAt = now
	s.sessions[session.UEID] = session
	return session
}

func (s *Store) Get(ueID string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.sessions[ueID]
	return v, ok
}

func (s *Store) Delete(ueID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, ueID)
}

func (s *Store) List() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Session, 0, len(s.sessions))
	for _, v := range s.sessions {
		out = append(out, v)
	}
	return out
}
