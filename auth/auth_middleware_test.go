package auth_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/asstart/go-session"
	smocks "github.com/asstart/go-session/mocks"
	"github.com/asstart/go-pseudo-passwordless/auth"
	"github.com/go-chi/chi"
	"github.com/go-logr/logr"
	"github.com/golang/mock/gomock"
	"github.com/steinfletcher/apitest"
	"github.com/stretchr/testify/assert"
)

func TestAuthNoCookie(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	cname := "sid"

	v, _, err := auth.RegistrateCustomVldtrs()
	assert.Nil(t, err)

	mw := auth.AuthMW{
		CookieName:        cname,
		SessionContextKey: "session",
		SService:          ssmock,
		Logger:            logr.Discard(),
		Vld:               v,
	}

	rootRouter := chi.NewRouter()
	rootRouter.Get("/unsecured", func(rw http.ResponseWriter, r *http.Request) {})
	rootRouter.Post("/unsecured", func(rw http.ResponseWriter, r *http.Request) {})
	rootRouter.Patch("/unsecured", func(rw http.ResponseWriter, r *http.Request) {})
	rootRouter.Put("/unsecured", func(rw http.ResponseWriter, r *http.Request) {})
	rootRouter.Head("/unsecured", func(rw http.ResponseWriter, r *http.Request) {})
	rootRouter.Delete("/unsecured", func(rw http.ResponseWriter, r *http.Request) {})

	securedRouter := chi.NewRouter()
	securedRouter.Use(mw.Auth())
	securedRouter.Get("/url", func(rw http.ResponseWriter, r *http.Request) {})

	rootRouter.Mount("/secured", securedRouter)

	tt := []struct {
		name         string
		method       string
		path         string
		expectedCode int
	}{
		{"secured root path", "GET", "/secured", http.StatusUnauthorized},
		{"secured path under root", "GET", "/secured/url", http.StatusUnauthorized},
		{"root path", "GET", "/", http.StatusNotFound},
		{"unsecured path", "GET", "/unsecured", http.StatusOK},

		{"secured root path", "POST", "/secured", http.StatusUnauthorized},
		{"secured path under root", "POST", "/secured/url", http.StatusUnauthorized},
		{"root path", "POST", "/", http.StatusNotFound},
		{"unsecured path", "POST", "/unsecured", http.StatusOK},

		{"secured root path", "PUT", "/secured", http.StatusUnauthorized},
		{"secured path under root", "PUT", "/secured/url", http.StatusUnauthorized},
		{"root path", "PUT", "/", http.StatusNotFound},
		{"unsecured path", "PUT", "/unsecured", http.StatusOK},

		{"secured root path", "PATCH", "/secured", http.StatusUnauthorized},
		{"secured path under root", "PATCH", "/secured/url", http.StatusUnauthorized},
		{"root path", "PATCH", "/", http.StatusNotFound},
		{"unsecured path", "PATCH", "/unsecured", http.StatusOK},

		{"secured root path", "HEAD", "/secured", http.StatusUnauthorized},
		{"secured path under root", "HEAD", "/secured/url", http.StatusUnauthorized},
		{"root path", "HEAD", "/", http.StatusNotFound},
		{"unsecured path", "HEAD", "/unsecured", http.StatusOK},

		{"secured root path", "DELETE", "/secured", http.StatusUnauthorized},
		{"secured path under root", "DELETE", "/secured/url", http.StatusUnauthorized},
		{"root path", "DELETE", "/", http.StatusNotFound},
		{"unsecured path", "DELETE", "/unsecured", http.StatusOK},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			apitest.
				New().
				Handler(rootRouter).
				Method(tc.method).
				URL(tc.path).
				Expect(t).
				Status(tc.expectedCode).
				End()
		})
	}
}

func TestAuthSessionNotLoaded(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	v, _, err := auth.RegistrateCustomVldtrs()
	assert.Nil(t, err)

	mw := auth.AuthMW{
		CookieName:        cname,
		SessionContextKey: "session",
		SService:          ssmock,
		Logger:            logr.Discard(),
		Vld:               v,
	}

	rootRouter := chi.NewRouter()

	securedRouter := chi.NewRouter()
	securedRouter.Use(mw.Auth())
	securedRouter.Get("/url", func(rw http.ResponseWriter, r *http.Request) {})

	rootRouter.Mount("/secured", securedRouter)

	tt := []struct {
		name string
		err  error
	}{
		{"loading failed error", errors.New("error loading")},
		{"session not found", session.ErrSessionNotFound},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ssmock.EXPECT().LoadSession(gomock.Any(), cvalue).Return(nil, tc.err)

			apitest.
				New().
				Handler(rootRouter).
				Method("GET").
				URL("/secured/url").
				Cookie(cname, cvalue).
				Expect(t).
				Status(http.StatusUnauthorized).
				End()
		})
	}
}

func TestAuthSessionExpired(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	v, _, err := auth.RegistrateCustomVldtrs()
	assert.Nil(t, err)

	mw := auth.AuthMW{
		CookieName:        cname,
		SessionContextKey: "session",
		SService:          ssmock,
		Logger:            logr.Discard(),
		Vld:               v,
	}

	rootRouter := chi.NewRouter()

	securedRouter := chi.NewRouter()
	securedRouter.Use(mw.Auth())
	securedRouter.Get("/url", func(rw http.ResponseWriter, r *http.Request) {})

	rootRouter.Mount("/secured", securedRouter)

	ssmock.EXPECT().LoadSession(gomock.Any(), cvalue).Return(&session.Session{
		ID:     "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q",
		Data:   make(map[string]interface{}),
		Opts:   session.DefaultCookieConf(),
		Anonym: false,
		Active: false,
	}, nil)

	apitest.
		New().
		Handler(rootRouter).
		Method("GET").
		URL("/secured/url").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusUnauthorized).
		End()
}

func TestAuthSessionAnon(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	v, _, err := auth.RegistrateCustomVldtrs()
	assert.Nil(t, err)

	mw := auth.AuthMW{
		CookieName:        cname,
		SessionContextKey: "session",
		SService:          ssmock,
		Logger:            logr.Discard(),
		Vld:               v,
	}

	rootRouter := chi.NewRouter()

	securedRouter := chi.NewRouter()
	securedRouter.Use(mw.Auth())
	securedRouter.Get("/url", func(rw http.ResponseWriter, r *http.Request) {})

	rootRouter.Mount("/secured", securedRouter)

	ssmock.EXPECT().LoadSession(gomock.Any(), cvalue).Return(&session.Session{
		ID:             "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q",
		Data:           make(map[string]interface{}),
		Opts:           session.DefaultCookieConf(),
		Anonym:         true,
		Active:         true,
		IdleTimeout:    10000 * time.Hour,
		AbsTimeout:     10000 * time.Hour,
		CreatedAt:      time.Now(),
		LastAccessedAt: time.Now(),
	}, nil)

	apitest.
		New().
		Handler(rootRouter).
		Method("GET").
		URL("/secured/url").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusUnauthorized).
		End()
}

func TestAuthOK(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	v, _, err := auth.RegistrateCustomVldtrs()
	assert.Nil(t, err)

	mw := auth.AuthMW{
		CookieName:        cname,
		SessionContextKey: "session",
		SService:          ssmock,
		Logger:            logr.Discard(),
		Vld:               v,
	}

	rootRouter := chi.NewRouter()

	securedRouter := chi.NewRouter()
	securedRouter.Use(mw.Auth())
	securedRouter.Get("/url", func(rw http.ResponseWriter, r *http.Request) {})

	rootRouter.Mount("/secured", securedRouter)

	ssmock.EXPECT().LoadSession(gomock.Any(), cvalue).Return(&session.Session{
		ID:             "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q",
		Data:           make(map[string]interface{}),
		Opts:           session.DefaultCookieConf(),
		UID:            "2222",
		Anonym:         false,
		Active:         true,
		IdleTimeout:    10000 * time.Hour,
		AbsTimeout:     10000 * time.Hour,
		CreatedAt:      time.Now(),
		LastAccessedAt: time.Now(),
	}, nil)

	apitest.
		New().
		Handler(rootRouter).
		Method("GET").
		URL("/secured/url").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusOK).
		End()
}

func TestInvalidSessionId(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	cname := "sid"
	invalidS := "1"

	v, _, err := auth.RegistrateCustomVldtrs()
	assert.Nil(t, err)

	mw := auth.AuthMW{
		CookieName:        cname,
		SessionContextKey: "session",
		SService:          ssmock,
		Logger:            logr.Discard(),
		Vld:               v,
	}

	rootRouter := chi.NewRouter()

	securedRouter := chi.NewRouter()
	securedRouter.Use(mw.Auth())
	securedRouter.Get("/url", func(rw http.ResponseWriter, r *http.Request) {})

	rootRouter.Mount("/secured", securedRouter)

	apitest.
		New().
		Handler(rootRouter).
		Method("GET").
		URL("/secured/url").
		Cookie(cname, invalidS).
		Expect(t).
		Status(http.StatusUnauthorized).
		CookieNotPresent(cname).
		End()
}
