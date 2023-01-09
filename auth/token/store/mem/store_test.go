package mem_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/asstart/go-pseudo-passwordless/auth/token"
	"github.com/asstart/go-pseudo-passwordless/auth/token/store/mem"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
)

func TestSaveMemStore(t *testing.T) {
	ms := mem.NewMemStore()

	store := mem.InMemTokenStore{
		Logger: logr.Discard(),
		Store:  ms,
	}

	code := "123456"
	exp := time.Now().Add(100 * time.Second)
	atmpt := 3
	uid := "111"

	tkn := token.CodeToken{
		Value:    code,
		ExpireAt: exp,
		OwnerID:  uid,
		Attempts: atmpt,
	}

	fmt.Printf("token: %v\n", tkn)

	store.Save(context.TODO(), &tkn)

	v, ok := ms.Storage[uid]
	assert.True(t, ok)
	assert.Equal(t, atmpt, v.Attempts)
	assert.Greater(t, v.ExpireAt, time.Now())
	assert.Equal(
		t,
		sha256.Sum256([]byte(code)),
		v.HashedToken,
	)
}
