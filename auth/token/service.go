package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/go-logr/logr"
)

var ErrTokenValidation = errors.New("tokenservice: invalid token format")
var ErrTokenVerification = errors.New("tokenservice: wrong token code")
var ErrTokenInactive = errors.New("tokenservice: token inactive")

type Service interface {
	Verify(ctx context.Context, ownerID string, code string) error
	CreateAndDeliver(ctx context.Context, ownerID string, destination string) error
}

type TokenService struct {
	Logger         logr.Logger
	Store          TokenStore
	Conf           TokenConfig
	Transport      TokenTransport
	MessageBuilder TokenMessageBuilder
	CtxReqIDKey    interface{}
}

func Validate(code string) error {
	ok, err := regexp.Match("^[0-9]{6}$", []byte(code))
	if err != nil {
		return ErrTokenValidation
	}
	if !ok {
		return ErrTokenValidation
	}
	return nil
}

func (ts *TokenService) Verify(ctx context.Context, ownerID string, code string) error {
	ts.Logger.V(10).Info("auth.token.Verify() started", "rquid", ctx.Value(ts.CtxReqIDKey))
	defer ts.Logger.V(10).Info("auth.token.Verify() finished", "rquid", ctx.Value(ts.CtxReqIDKey))

	tkn, err := ts.Store.DecreaseAttemptAndLoadLatest(ctx, ownerID)

	if err == ErrNoTokenFound {
		return ErrTokenInactive
	}

	if err != nil {
		return err
	}

	if tkn.ExpireAt.Before(time.Now()) {
		ts.Logger.V(0).Info(
			"auth.token.Verify() token expired",
			"rquid", ctx.Value(ts.CtxReqIDKey),
		)
		return ErrTokenInactive
	}

	if tkn.Attempts < 0 {
		ts.Logger.V(0).Info(
			"auth.token.Verify() no attemtps left",
			"rquid", ctx.Value(ts.CtxReqIDKey),
		)
		return ErrTokenInactive
	}

	hashedCode := hashCode(code)

	if tkn.HashedValue != hashedCode {
		ts.Logger.V(0).Info(
			"auth.mongo.Verify() wrong code",
			"rquid", ctx.Value(ts.CtxReqIDKey),
		)
		return ErrTokenVerification
	}

	return nil
}

func (ts *TokenService) CreateAndDeliver(ctx context.Context, ownerID string, destination string) error {
	ts.Logger.V(10).Info("auth.token.CreateAndDeliver() started", "rquid", ctx.Value(ts.CtxReqIDKey))
	defer ts.Logger.V(10).Info("auth.token.CreateAndDeliver() finished", "rquid", ctx.Value(ts.CtxReqIDKey))

	token, err := ts.generateToken(ownerID)
	if err != nil {
		err = fmt.Errorf("auth.token.CreateAndDeliver() generateToken error: %w", err)
		ts.Logger.V(0).Info(
			"auth.token.CreateAndDeliver() generateToken error",
			"rquid", ctx.Value(ts.CtxReqIDKey),
			"err", err)
		return err
	}

	err = ts.Store.Save(ctx, token)
	if err != nil {
		err = fmt.Errorf("auth.token.CreateAndDeliver() save error: %w", err)
		ts.Logger.V(0).Info(
			"auth.token.CreateAndDeliver() Save error",
			"rquid", ctx.Value(ts.CtxReqIDKey),
			"err", err)
		return err
	}

	msg, err := ts.MessageBuilder.GetMessage(token)
	if err != nil {
		err = fmt.Errorf("auth.token.CreateAndDeliver() GetMessage error: %w", err)
		ts.Logger.V(0).Info(
			"auth.token.CreateAndDeliver() GetMessage error",
			"rquid", ctx.Value(ts.CtxReqIDKey),
			"err", err)
		return err
	}

	go ts.Transport.Send(ctx, msg, destination)

	return nil
}

type CodeToken struct {
	Value       string
	HashedValue [32]byte
	ExpireAt    time.Time
	OwnerID     string
	Attempts    int
}

func (ts *TokenService) generateToken(uid string) (*CodeToken, error) {

	code, err := generateCode()

	if err != nil {
		return nil, fmt.Errorf("error generating token: %w", err)
	}

	now := time.Now()
	duration, err := ts.Conf.GetDuration()
	if err != nil {
		return nil, err
	}

	exp := now.Add(duration)

	atmpt, err := ts.Conf.GetAttempts()
	if err != nil {
		return nil, err
	}

	return &CodeToken{
		Value:       code,
		HashedValue: hashCode(code),
		ExpireAt:    exp,
		OwnerID:     uid,
		Attempts:    atmpt,
	}, nil
}

func hashCode(code string) [32]byte {
	return sha256.Sum256([]byte(code))
}

func generateCode() (string, error) {
	s, err := randomSeq(6, []byte("0123456789"))
	if err != nil {
		return "", err
	}
	return string(s), nil
}

func randomSeq(n int, alphabet []byte) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	alphLen := len(alphabet)
	if alphLen < 2 || alphLen > 256 {
		return nil, fmt.Errorf("alhabet should have at least 2 symbols")
	}

	// output of system random is a sequence of bytes
	// if we want to get output result consisted of certain symbols
	// we can do alphabet[randomByte % len(alphabet)]
	// randomByte is in range [0,255]
	// so we can stuck in situtation where symbols with different indexes
	// in an alphabet may have different probability to appear in the output
	//
	// for instance:
	//
	// len(alphabet) = 10
	// if we will use any byte from random output to calculate modulo
	// we will see that symbols from alphabet with indexes 0-6
	// will have higher probability to appear in the output
	// than symbols with indexes 7-9
	//
	// thats way we need to calculate max byte value from random output
	// to provide uniform distribution for every symbol of alphabet
	maxByteVal := 255 - (256 % alphLen)
	// make read buffer bigger than needed output, to try create output
	// with one read from system random
	bufSize := int(float32(n) * 1.5)
	if bufSize > 2048 {
		bufSize = 2048
	}

	buf := make([]byte, bufSize)
	out := make([]byte, n)
	i := 0
	for {
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("error reading system random: %w", err)
		}
		for _, b := range buf {
			c := int(b)
			// populate out only if random is les then available max byte
			// to provide uniform distribution of alphabet symbols in the output
			if c <= maxByteVal {
				out[i] = alphabet[c%alphLen]
				i++
				if i == n {
					return out, nil
				}
			}
		}
	}
}
