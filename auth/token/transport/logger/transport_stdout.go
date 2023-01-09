package token

import (
	"context"

	"github.com/go-logr/logr"
)

type LoggerTransport struct {
	Logger logr.Logger
}

func (s *LoggerTransport) Send(ctx context.Context, msg, receiver string) error {
	s.Logger.V(0).Info("[LoggerTransport only for testing]", "msg", msg, "receiver", receiver)
	return nil
}
