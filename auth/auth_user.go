package auth

type AuthUser interface {
	GetID() string
}

type AuthUserService interface {
	GetUserByKey(key string) (AuthUser, error)
}
