package token

import "context"

type Transport interface {
	Send(ctx context.Context, msg string, receiver string) error
}
