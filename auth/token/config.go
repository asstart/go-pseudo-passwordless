package token

import (
	"time"
)

type TokenConfig interface {
	GetDuration() (time.Duration, error)
	GetAttempts() (int, error)
}

type SimpleTokenConfig struct {
	Duration time.Duration
	Attempts int
}

func (c *SimpleTokenConfig) GetDuration() (time.Duration, error) {
	return c.Duration, nil
}
func (c *SimpleTokenConfig) GetAttempts() (int, error) {
	return c.Attempts, nil
}
