package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/asstart/go-pseudo-passwordless/auth/token"
	"github.com/go-logr/logr"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoStore struct {
	Collection  *mongo.Collection
	Logger      logr.Logger
	CtxReqIDKey interface{}
}

type mngToken struct {
	ID          primitive.ObjectID `bson:"_id"`
	HashedValue [32]byte           `bson:"hashed_value"`
	OwnerID     string             `bson:"owner_id"`
	Attempts    int                `bson:"attempts"`
	ExpiredAt   time.Time          `bson:"expired_at"`
}

func (ms *MongoStore) Save(ctx context.Context, token *token.CodeToken) error {
	ms.Logger.V(10).Info("auth.token.mongo.Save() started", "rquid", ctx.Value(ms.CtxReqIDKey))
	defer ms.Logger.V(10).Info("auth.token.mongo.Save() finished", "rquid", ctx.Value(ms.CtxReqIDKey))

	id := primitive.NewObjectID()
	f := bson.M{"_id": id}
	obj := bson.M{"$set": bson.M{
		"hashed_value": token.HashedValue,
		"owner_id":     token.OwnerID,
		"attempts":     token.Attempts,
		"expired_at":   token.ExpireAt,
	}}
	opt := options.Update()
	opt.SetUpsert(true)

	ur, err := ms.Collection.UpdateOne(
		ctx,
		f,
		obj,
		opt,
	)

	if err != nil {
		err = fmt.Errorf("auth.token.mongo.Save() UpdateOne() error: %w", err)
		ms.Logger.V(0).Info(
			"auth.token.mongo.Save() UpdateOne() error",
			"rquid", ctx.Value(ms.CtxReqIDKey),
			"err", err,
		)
		return err
	}

	if ur.UpsertedCount != 1 {
		err = fmt.Errorf("auth.token.mongo.Save() UpdateOne() count of upserted want 1, got: %v", ur.UpsertedCount)
		ms.Logger.V(0).Info(
			"auth.token.mongo.Save() UpdateOne() error",
			"rquid", ctx.Value(ms.CtxReqIDKey),
			"err", err,
		)
		return err
	}

	return nil
}

func (ms *MongoStore) DecreaseAttemptAndLoadLatest(ctx context.Context, ownerID string) (*token.CodeToken, error) {
	ms.Logger.V(10).Info("auth.token.mongo.DecreaseAttemptAndLoadLatest() started", "rquid", ctx.Value(ms.CtxReqIDKey))
	defer ms.Logger.V(10).Info("auth.token.mongo.DecreaseAttemptAndLoadLatest() finished", "rquid", ctx.Value(ms.CtxReqIDKey))

	f := bson.M{"owner_id": ownerID}
	opt := options.FindOneAndUpdate()
	opt.SetReturnDocument(options.After)
	opt.SetSort(bson.M{"_id": -1})
	upd := bson.M{
		"$inc": bson.M{
			"attempts": -1,
		},
	}

	sr := ms.Collection.FindOneAndUpdate(
		ctx,
		f,
		upd,
		opt,
	)

	if sr.Err() == mongo.ErrNoDocuments {
		ms.Logger.V(0).Info(
			"auth.token.mongo.DecreaseAttemptAndLoadLatest() FindOneAndUpdate() no documents found",
			"rquid", ctx.Value(ms.CtxReqIDKey),
			"owner_id", ownerID,
		)
		return nil, token.ErrNoTokenFound
	}

	if sr.Err() != nil {
		err := fmt.Errorf("auth.mongo.DecreaseAttemptAndLoadLatest() FindOneAndUpdate() error: %w", sr.Err())
		ms.Logger.V(0).Info(
			"auth.token.mongo.DecreaseAttemptAndLoadLatest() FindOneAndUpdate() error",
			"rquid", ctx.Value(ms.CtxReqIDKey),
			"err", err,
		)
		return nil, err
	}

	var tkn mngToken
	err := sr.Decode(&tkn)
	if err != nil {
		err = fmt.Errorf("auth.mongo.DecreaseAttemptAndLoadLatest() Decode() error: %w", err)
		ms.Logger.V(0).Info(
			"auth.token.mongo.DecreaseAttemptAndLoadLatest() Decode() error",
			"rquid", ctx.Value(ms.CtxReqIDKey),
			"err", err,
		)
		return nil, err
	}

	return &token.CodeToken{
		Value:       "",
		OwnerID:     "",
		HashedValue: tkn.HashedValue,
		ExpireAt:    tkn.ExpiredAt,
		Attempts:    tkn.Attempts,
	}, nil
}
