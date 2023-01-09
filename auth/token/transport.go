package token

import "context"

type TokenTransport interface {
	Send(ctx context.Context, msg string, receiver string) error
}
