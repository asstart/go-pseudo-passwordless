package token

import (
	"context"
	"errors"
)

var ErrNoTokenFound = errors.New("token_store: token not found")

type TokenStore interface {
	Save(ctx context.Context, token *CodeToken) error
	DecreaseAttemptAndLoadLatest(ctx context.Context, uid string) (*CodeToken, error)
}
