package mem

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/asstart/go-pseudo-passwordless/auth/token"
	"github.com/go-logr/logr"
)

type InMemTokenStore struct {
	Logger logr.Logger
	Store  *MemStore
}

type MemStore struct {
	Storage map[string]memToken
	mutex   sync.Mutex
}

type memToken struct {
	HashedToken [32]byte
	ExpireAt    time.Time
	Attempts    int
}

func NewMemStore() *MemStore {

	storage := make(map[string]memToken)

	s := MemStore{
		Storage: storage,
	}

	return &s
}

func (s *InMemTokenStore) Save(ctx context.Context, token *token.CodeToken) error {

	hashed := sha256.Sum256([]byte(token.Value))

	mt := memToken{
		HashedToken: hashed,
		ExpireAt:    token.ExpireAt,
		Attempts:    token.Attempts,
	}

	s.Store.mutex.Lock()
	defer s.Store.mutex.Unlock()

	s.Store.Storage[token.OwnerID] = mt

	return nil
}

func (s *InMemTokenStore) DecreaseAttemptAndLoadLatest(ctx context.Context, ownerID string) (*token.CodeToken, error) {
	s.Store.mutex.Lock()
	defer s.Store.mutex.Unlock()

	mt, _ := s.load(ctx, ownerID)

	if mt == nil {
		s.Logger.Info("code not found", "uid", ownerID)
		return nil, token.ErrNoTokenFound
	}

	mt.Attempts -= 1
	s.Store.Storage[ownerID] = *mt

	return &token.CodeToken{
		Value:       "",
		OwnerID:     "",
		HashedValue: mt.HashedToken,
		ExpireAt:    mt.ExpireAt,
		Attempts:    mt.Attempts,
	}, nil
}

func (s *InMemTokenStore) load(ctx context.Context, uid string) (*memToken, error) {

	v, ok := s.Store.Storage[uid]
	if !ok {
		return nil, nil
	}

	return &v, nil
}
