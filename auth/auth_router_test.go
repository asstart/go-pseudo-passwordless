package auth_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/asstart/go-session"
	smocks "github.com/asstart/go-session/mocks"
	"github.com/asstart/go-pseudo-passwordless/auth"
	amocks "github.com/asstart/go-pseudo-passwordless/auth/mocks"
	"github.com/asstart/go-pseudo-passwordless/auth/token"
	tmocks "github.com/asstart/go-pseudo-passwordless/auth/token/mocks"
	"github.com/go-logr/logr"
	"github.com/golang/mock/gomock"
	"github.com/steinfletcher/apitest"
	"github.com/stretchr/testify/assert"
)

type ProcessLoginDataMatcher struct {
	loginMatcher       gomock.Matcher
	attempMacher       gomock.Matcher
	canResendAtMatcher InRangeMartcher
}

func (pldm ProcessLoginDataMatcher) Matches(x interface{}) bool {
	v, ok := x.(auth.ProcessLoginData)
	if !ok {
		return false
	}

	ok = pldm.loginMatcher.Matches(v.Login)
	if !ok {
		return false
	}

	ok = pldm.attempMacher.Matches(v.Attempts)
	if !ok {
		return false
	}

	ok = pldm.canResendAtMatcher.Matches(v.CanResendAt)

	return ok
}

func (pldm ProcessLoginDataMatcher) String() string {
	return fmt.Sprintf("login: %v, attempts: %v, canResendRange:%v",
		pldm.loginMatcher.String(),
		pldm.attempMacher.String(),
		pldm.canResendAtMatcher.String())
}

type InRangeMartcher struct {
	delta time.Duration
	x     interface{}
}

func (aft InRangeMartcher) Matches(x interface{}) bool {
	if aft.x == nil || x == nil {
		return false
	}

	v1, ok := aft.x.(time.Time)
	if !ok {
		return false
	}

	v2, ok := x.(time.Time)
	if !ok {
		return false
	}

	return v2.After(v1.Add(-1*aft.delta)) && v2.Before(v1.Add(aft.delta))
}

func (aft InRangeMartcher) String() string {
	return fmt.Sprintf("%v", aft.x)
}

func TestInvalidRoutes(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	tt := []struct {
		method string
		route  string
	}{
		{"GET", "/login"},
		{"PUT", "/login"},
		{"PATCH", "/login"},
		{"HEAD", "/login"},
		{"DELETE", "/login"},
		{"GET", "/verify"},
		{"PUT", "/verify"},
		{"PATCH", "/verify"},
		{"HEAD", "/verify"},
		{"DELETE", "/verify"},
		{"POST", "/logout"},
		{"PUT", "/logout"},
		{"PATCH", "/logout"},
		{"HEAD", "/logout"},
		{"DELETE", "/logout"},
	}

	for _, tc := range tt {
		apitest.
			New().
			Handler(router).
			Method(tc.method).
			URL(tc.route).
			Header("Content-Type", "application/json").
			Expect(t).
			Status(http.StatusMethodNotAllowed).
			CookieNotPresent(cname).
			End()
	}
}

func TestUnsupportedMediaType(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	tt := []struct {
		method string
		route  string
		body   string
	}{
		{"POST", "/login", `{"login":"123@test.mail"}`},
		{"POST", "/verify", `{"token":"123456"}`},
	}

	for _, tc := range tt {
		apitest.
			New().
			Handler(router).
			Method(tc.method).
			URL(tc.route).
			Body(tc.body).
			Expect(t).
			Status(http.StatusUnsupportedMediaType).
			CookieNotPresent(cname).
			End()
	}
}

func TestSuccessfullLogin(t *testing.T) {

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	sid := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	login := "123@test.mail"
	rbody := fmt.Sprintf(`{"login":"%v"}`, login)
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	ssmock := smocks.NewMockService(gomock.NewController(t))

	csres := ssmock.
		EXPECT().
		CreateAnonymSession(gomock.Any(),
			gomock.Eq(cconf),
			gomock.Eq(sconf),
			gomock.Eq("login"),
			ProcessLoginDataMatcher{
				loginMatcher: gomock.Eq(login),
				attempMacher: gomock.Eq(resendAttempt),
				canResendAtMatcher: InRangeMartcher{
					delta: 100 * time.Millisecond,
					x:     time.Now().Add(resendTimeout),
				},
			},
		).
		Return(
			&session.Session{
				ID:     sid,
				Data:   make(map[string]interface{}),
				Opts:   cconf,
				Anonym: true,
				Active: true,
			},
			nil,
		).
		Times(1)

	tsmock := tmocks.NewMockService(gomock.NewController(t))

	tsmock.
		EXPECT().
		CreateAndDeliver(gomock.Any(), sid, login).
		Return(nil).
		After(csres)

	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	umock.
		EXPECT().
		GetUserByKey(gomock.Any()).
		MaxTimes(0)

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)

	assert.Nil(t, err)

	apitest.
		New().
		Handler(router).
		Method("POST").
		URL("/login").
		Header("Content-Type", "application/json").
		Body(rbody).
		Expect(t).
		Status(200).
		Cookie(cname, sid).
		End()
}

func TestResendCookieNotFound(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	expBody, _ := json.Marshal(auth.ErrorResponse{
		Code:    33,
		Message: "not available to resend code",
	})

	apitest.
		New().
		Handler(router).
		Method(http.MethodGet).
		URL("/send").
		Header("Content-Type", "application/json").
		Expect(t).
		CookieNotPresent(cname).
		Status(http.StatusBadRequest).
		Body(string(expBody)).
		End()
}

func TestResendSIDValidationFail(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "bad id"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	apitest.
		New().
		Handler(router).
		Method(http.MethodGet).
		URL("/send").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusBadRequest).
		Cookie(cname, "").
		End()
}

func TestResendLoadSessionFailed(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	tt := []struct {
		name   string
		retErr error
	}{
		{"session not found error", session.ErrSessionNotFound},
		{"any error", errors.New("smth goes wrong")},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ssmock.
				EXPECT().
				LoadSession(gomock.Any(), gomock.Eq(cvalue)).
				Return(nil, tc.retErr)
		})

		apitest.
			New().
			Handler(router).
			Method(http.MethodGet).
			URL("/send").
			Header("Content-Type", "application/json").
			Cookie(cname, cvalue).
			Expect(t).
			Status(http.StatusInternalServerError).
			End()
	}
}

func TestResendNotAvailableWrongSession(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	retBody, _ := json.Marshal(auth.ErrorResponse{
		Code:    33,
		Message: "not available to resend code",
	})

	tt := []struct {
		name       string
		retSession session.Session
	}{
		{"session expired", session.Session{
			ID:     cvalue,
			Opts:   session.DefaultCookieConf(),
			Anonym: true, Active: false,
			IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
			CreatedAt: time.Now(), LastAccessedAt: time.Now()},
		},
		{"session not anon", session.Session{
			ID:     cvalue,
			Opts:   session.DefaultCookieConf(),
			Anonym: false, Active: true,
			IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
			CreatedAt: time.Now(), LastAccessedAt: time.Now()},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ssmock.
				EXPECT().
				LoadSession(gomock.Any(), gomock.Eq(cvalue)).
				Return(&tc.retSession, nil)
		})

		apitest.
			New().
			Handler(router).
			Method(http.MethodGet).
			URL("/send").
			Header("Content-Type", "application/json").
			Cookie(cname, cvalue).
			Expect(t).
			Status(http.StatusBadRequest).
			Body(string(retBody)).
			CookieNotPresent(cname).
			End()
	}
}

func TestResendNotAvailableResendParamsNotFoundInSession(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	retBody, _ := json.Marshal(auth.ErrorResponse{
		Code:    33,
		Message: "not available to resend code",
	})

	ses := session.Session{
		ID:     cvalue,
		Opts:   session.DefaultCookieConf(),
		Anonym: true, Active: true,
		IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
		CreatedAt: time.Now(), LastAccessedAt: time.Now(),
	}

	lsm := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), gomock.Eq(cvalue)).
		Return(&ses, nil)

	ssmock.
		EXPECT().
		InvalidateSession(gomock.Any(), gomock.Eq(cvalue)).
		Return(nil).
		After(lsm)

	apitest.
		New().
		Handler(router).
		Method(http.MethodGet).
		URL("/send").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusBadRequest).
		Body(string(retBody)).
		Cookie(cname, "").
		End()
}

func TestResendNotAvailableNoAttemptsLeft(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"
	login := "new@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	ses := session.Session{
		ID: cvalue,
		Data: map[string]interface{}{
			"login": map[string]interface{}{
				"login":       login,
				"attempts":    0,
				"canresendat": time.Now().Add(resendTimeout),
			},
		},
		Opts:   session.DefaultCookieConf(),
		Anonym: true, Active: true,
		IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
		CreatedAt: time.Now(), LastAccessedAt: time.Now(),
	}
	expResp, _ := json.Marshal(auth.ErrorResponse{
		Code:    31,
		Message: "attempts to resend expired",
	})

	lsmock := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), gomock.Eq(cvalue)).
		Return(&ses, nil)

	ssmock.
		EXPECT().
		InvalidateSession(gomock.Any(), cvalue).
		Return(nil).
		After(lsmock)

	apitest.
		New().
		Handler(router).
		Method(http.MethodGet).
		URL("/send").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusBadRequest).
		Body(string(expResp)).
		Cookie(cname, "").
		End()

}

func TestResendNotAvailableTimeoutNotExpiredYet(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"
	login := "new@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	ses := session.Session{
		ID: cvalue,
		Data: map[string]interface{}{
			"login": map[string]interface{}{
				"login":       login,
				"attempts":    resendAttempt,
				"canresendat": time.Now().Add(resendTimeout),
			},
		},
		Opts:   session.DefaultCookieConf(),
		Anonym: true, Active: true,
		IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
		CreatedAt: time.Now(), LastAccessedAt: time.Now(),
	}
	expResp, _ := json.Marshal(auth.ErrorResponse{
		Code:    32,
		Message: "resend timeout not expired",
	})

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), gomock.Eq(cvalue)).
		Return(&ses, nil)

	apitest.
		New().
		Handler(router).
		Method(http.MethodGet).
		URL("/send").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusBadRequest).
		Body(string(expResp)).
		CookieNotPresent(cname).
		End()
}

func TestResendUpdateSessionFailed(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"
	login := "new@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	ses := session.Session{
		ID: cvalue,
		Data: map[string]interface{}{
			"login": map[string]interface{}{
				"login":       login,
				"attempts":    resendAttempt,
				"canresendat": time.Now().Add(-2 * resendTimeout),
			},
		},
		Opts:   session.DefaultCookieConf(),
		Anonym: true, Active: true,
		IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
		CreatedAt: time.Now(), LastAccessedAt: time.Now(),
	}

	updatedAttmpts := resendAttempt - 1

	lsmock := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), gomock.Eq(cvalue)).
		Return(&ses, nil)

	ssmock.
		EXPECT().
		AddAttributes(
			gomock.Any(),
			gomock.Eq(cvalue),
			"login", ProcessLoginDataMatcher{
				loginMatcher: gomock.Eq(login),
				attempMacher: gomock.Eq(updatedAttmpts),
				canResendAtMatcher: InRangeMartcher{
					x:     time.Now().Add(resendTimeout),
					delta: 100 * time.Millisecond,
				},
			}).
		Return(nil, errors.New("something goes wrong")).
		After(lsmock)

	apitest.
		New().
		Handler(router).
		Method(http.MethodGet).
		URL("/send").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusInternalServerError).
		CookieNotPresent(cname).
		End()
}

func TestResendCreateTokenFailed(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"
	login := "new@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	ses := session.Session{
		ID: cvalue,
		Data: map[string]interface{}{
			"login": map[string]interface{}{
				"login":       login,
				"attempts":    resendAttempt,
				"canresendat": time.Now().Add(-2 * resendTimeout),
			},
		},
		Opts:   session.DefaultCookieConf(),
		Anonym: true, Active: true,
		IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
		CreatedAt: time.Now(), LastAccessedAt: time.Now(),
	}

	lsmock := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), gomock.Eq(cvalue)).
		Return(&ses, nil)

	updatedAttempts := resendAttempt - 1

	updatedSes := session.Session{
		ID: cvalue,
		Data: map[string]interface{}{
			"login": map[string]interface{}{
				"login":       login,
				"attempts":    updatedAttempts,
				"canresendat": time.Now().Add(-2 * resendTimeout),
			},
		},
		Opts:   session.DefaultCookieConf(),
		Anonym: true, Active: true,
		IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
		CreatedAt: time.Now(), LastAccessedAt: time.Now(),
	}

	updsesmock := ssmock.
		EXPECT().
		AddAttributes(
			gomock.Any(),
			gomock.Eq(cvalue),
			"login", ProcessLoginDataMatcher{
				loginMatcher: gomock.Eq(login),
				attempMacher: gomock.Eq(updatedAttempts),
				canResendAtMatcher: InRangeMartcher{
					delta: 100 * time.Millisecond,
					x:     time.Now().Add(resendTimeout),
				},
			}).
		Return(&updatedSes, nil).
		After(lsmock)

	tsmock.
		EXPECT().
		CreateAndDeliver(gomock.Any(), gomock.Eq(updatedSes.ID), gomock.Eq(login)).
		Return(errors.New("something goes wrong")).
		After(updsesmock)

	apitest.
		New().
		Handler(router).
		Method(http.MethodGet).
		URL("/send").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusInternalServerError).
		CookieNotPresent(cname).
		End()
}

func TestResendCode(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()

	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"
	login := "new@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	ses := session.Session{
		ID: cvalue,
		Data: map[string]interface{}{
			"login": map[string]interface{}{
				"login":       login,
				"attempts":    resendAttempt,
				"canresendat": time.Now().Add(-2 * resendTimeout),
			},
		},
		Opts:   session.DefaultCookieConf(),
		Anonym: true, Active: true,
		IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
		CreatedAt: time.Now(), LastAccessedAt: time.Now(),
	}

	lsmock := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), gomock.Eq(cvalue)).
		Return(&ses, nil)

	updatedAttmpt := resendAttempt - 1

	updatedSes := session.Session{
		ID: cvalue,
		Data: map[string]interface{}{
			"login": map[string]interface{}{
				"login":       login,
				"attempts":    updatedAttmpt,
				"canresendat": time.Now().Add(resendTimeout),
			},
		},
		Opts:   session.DefaultCookieConf(),
		Anonym: true, Active: true,
		IdleTimeout: 1 * time.Minute, AbsTimeout: 1 * time.Minute,
		CreatedAt: time.Now(), LastAccessedAt: time.Now(),
	}

	updsesmock := ssmock.
		EXPECT().
		AddAttributes(
			gomock.Any(),
			gomock.Eq(cvalue),
			"login", ProcessLoginDataMatcher{
				loginMatcher: gomock.Eq(login),
				attempMacher: gomock.Eq(updatedAttmpt),
				canResendAtMatcher: InRangeMartcher{
					x:     time.Now().Add(resendTimeout),
					delta: 100 * time.Millisecond,
				},
			}).
		Return(&updatedSes, nil).
		After(lsmock)

	tsmock.
		EXPECT().
		CreateAndDeliver(gomock.Any(), gomock.Eq(updatedSes.ID), gomock.Eq(login)).
		Return(nil).
		After(updsesmock)

	apitest.
		New().
		Handler(router).
		Method(http.MethodGet).
		URL("/send").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusOK).
		CookieNotPresent(cname).
		End()
}

func TestLoginSessionLoadFail(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	login := "123@test.mail"
	rbody := fmt.Sprintf(`{"login":"%v"}`, login)

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(
			nil,
			errors.New("load session error"),
		).
		Times(1)

	apitest.
		New().
		Handler(router).
		Method("POST").
		URL("/login").
		Header("Content-Type", "application/json").
		Body(rbody).
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusInternalServerError).
		End()
}

func TestLoginNotAnonymSessionFound(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	login := "123@test.mail"
	rbody := fmt.Sprintf(`{"login":"%v"}`, login)

	ses := session.Session{
		ID:             cvalue,
		Data:           make(map[string]interface{}),
		Opts:           cconf,
		Anonym:         false,
		Active:         true,
		IdleTimeout:    10000 * time.Hour,
		AbsTimeout:     10000 * time.Hour,
		CreatedAt:      time.Now(),
		LastAccessedAt: time.Now(),
	}

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(
			&ses,
			nil,
		).
		Times(1)

	expBody := auth.ErrorResponse{
		Code:    11,
		Message: "already logged in",
	}

	expBodyStr, _ := json.Marshal(expBody)

	apitest.
		New().
		Handler(router).
		Method("POST").
		URL("/login").
		Header("Content-Type", "application/json").
		Body(rbody).
		Cookie(cname, cvalue).
		Expect(t).
		Status(http.StatusBadRequest).
		Body(string(expBodyStr)).
		End()
}

func TestLoginBadRequestBody(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	expBodyBadBody := auth.ErrorResponse{
		Code:    2,
		Message: "bad request body",
	}
	expBodyBadBodyStr, _ := json.Marshal(expBodyBadBody)

	expBodyReqValidation := auth.ErrorValidationResponse{
		Code:    1,
		Message: "validation failed",
		Details: []auth.ValidationError{
			{
				Field:   "Login",
				Message: "Login is required",
			},
		},
	}
	expBodyReqValidationStr, _ := json.Marshal(expBodyReqValidation)

	expBodyEmailValidation := auth.ErrorValidationResponse{
		Code:    1,
		Message: "validation failed",
		Details: []auth.ValidationError{
			{
				Field:   "Login",
				Message: "should be email",
			},
		},
	}
	expBodyEmailValidationStr, _ := json.Marshal(expBodyEmailValidation)

	tt := []struct {
		name         string
		expectedBody []byte
		body         string
	}{
		{"wrong field", expBodyBadBodyStr, `{"wrongfield":"123@test.mail"}`},
		{"empty body", expBodyBadBodyStr, ""},
		{"no fields body", expBodyReqValidationStr, "{}"},
		{"not email", expBodyEmailValidationStr, `{"login":"12345"}`},
	}

	for _, tc := range tt {
		t.Run(
			tc.name, func(t *testing.T) {
				apitest.
					New().
					Handler(router).
					Method("POST").
					URL("/login").
					Header("Content-Type", "application/json").
					Body(tc.body).
					Expect(t).
					Status(http.StatusBadRequest).
					Body(string(tc.expectedBody)).
					CookieNotPresent(cname).
					End()
			},
		)

	}
}

func TestLoginCreateAnonSessionError(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"

	login := "123@test.mail"
	rbody := fmt.Sprintf(`{"login":"%v"}`, login)
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	ssmock.
		EXPECT().
		CreateAnonymSession(
			gomock.Any(),
			gomock.Eq(cconf),
			gomock.Eq(sconf),
			gomock.Eq("login"), ProcessLoginDataMatcher{
				loginMatcher: gomock.Eq(login),
				attempMacher: gomock.Eq(resendAttempt),
				canResendAtMatcher: InRangeMartcher{
					x:     time.Now().Add(resendTimeout),
					delta: 100 * time.Millisecond,
				},
			}).
		Return(
			nil,
			errors.New("create session error"),
		).
		Times(1)

	apitest.
		New().
		Handler(router).
		Method("POST").
		URL("/login").
		Header("Content-Type", "application/json").
		Body(rbody).
		Expect(t).
		Status(http.StatusInternalServerError).
		Body("").
		CookieNotPresent(cname).
		End()
}

func TestLoginGenerateTokenError(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	login := "123@test.mail"
	rbody := fmt.Sprintf(`{"login":"%v"}`, login)
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	ssmock.
		EXPECT().
		CreateAnonymSession(
			gomock.Any(),
			gomock.Eq(cconf),
			gomock.Eq(sconf),
			gomock.Eq("login"), ProcessLoginDataMatcher{
				loginMatcher: gomock.Eq(login),
				attempMacher: gomock.Eq(resendAttempt),
				canResendAtMatcher: InRangeMartcher{
					x:     time.Now().Add(resendTimeout),
					delta: 100 * time.Millisecond,
				},
			}).
		Return(
			&session.Session{
				ID:     cvalue,
				Data:   make(map[string]interface{}),
				Opts:   cconf,
				Anonym: true,
				Active: true,
			},
			nil,
		).
		Times(1)

	tsmock.
		EXPECT().
		CreateAndDeliver(gomock.Any(), gomock.Eq(cvalue), gomock.Eq(login)).
		Return(errors.New("error token gen"))

	apitest.
		New().
		Handler(router).
		Method("POST").
		URL("/login").
		Header("Content-Type", "application/json").
		Body(rbody).
		Expect(t).
		Status(http.StatusInternalServerError).
		Body("").
		CookieNotPresent(cname).
		End()
}

func TestLoginSendTokenError(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	login := "123@test.mail"
	rbody := fmt.Sprintf(`{"login":"%v"}`, login)
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	ssmock.
		EXPECT().
		CreateAnonymSession(
			gomock.Any(),
			gomock.Eq(cconf),
			gomock.Eq(sconf),
			gomock.Eq("login"), ProcessLoginDataMatcher{
				loginMatcher: gomock.Eq(login),
				attempMacher: gomock.Eq(resendAttempt),
				canResendAtMatcher: InRangeMartcher{
					x:     time.Now().Add(resendTimeout),
					delta: 100 * time.Millisecond,
				},
			}).
		Return(
			&session.Session{
				ID:     cvalue,
				Data:   make(map[string]interface{}),
				Opts:   cconf,
				Anonym: true,
				Active: true,
			},
			nil,
		).
		Times(1)

	tsmock.
		EXPECT().
		CreateAndDeliver(gomock.Any(), gomock.Eq(cvalue), gomock.Eq(login)).
		Return(errors.New("send token error"))

	apitest.
		New().
		Handler(router).
		Method("POST").
		URL("/login").
		Header("Content-Type", "application/json").
		Body(rbody).
		Expect(t).
		Status(http.StatusInternalServerError).
		Body("").
		CookieNotPresent(cname).
		End()
}

func TestLoginInvalidSessionIdFormat(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "bad id"

	login := "123@test.mail"
	rbody := fmt.Sprintf(`{"login":"%v"}`, login)
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	apitest.
		New().
		Handler(router).
		Method("POST").
		URL("/login").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusBadRequest).
		Cookie(cname, "").
		End()
}

func TestVerifyNoCookie(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	tkn := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, tkn)

	notAvailableToVerify := auth.ErrorResponse{
		Code:    21,
		Message: "not available to verify code",
	}
	notAvailableToVerifyStr, _ := json.Marshal(notAvailableToVerify)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Body(rbody).
		Expect(t).
		Status(http.StatusBadRequest).
		CookieNotPresent(cname).
		Body(string(notAvailableToVerifyStr)).
		End()
}

func TestVerifySessionLoadFailed(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	tkn := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, tkn)

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(nil, errors.New("error loading session"))

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusInternalServerError).
		CookieNotPresent(cname).
		End()
}

func TestVerifySeesionNotFound(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	tkn := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, tkn)

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(nil, session.ErrSessionNotFound)

	notAvailableToVerify := auth.ErrorResponse{
		Code:    21,
		Message: "not available to verify code",
	}
	notAvailableToVerifyStr, _ := json.Marshal(notAvailableToVerify)

	invalidatedCookieV := ""

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusBadRequest).
		Cookie(cname, invalidatedCookieV).
		Body(string(notAvailableToVerifyStr)).
		End()
}

func TestVerifyNotAnonymSessionFound(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	token := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, token)

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           make(map[string]interface{}),
			Opts:           cconf,
			Anonym:         false,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil)

	expBody := auth.ErrorResponse{
		Code:    11,
		Message: "already logged in",
	}

	expBodyStr, _ := json.Marshal(expBody)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusBadRequest).
		CookieNotPresent(cname).
		Body(string(expBodyStr)).
		End()
}

func TestVerifySessionExpired(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	token := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, token)

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           make(map[string]interface{}),
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    1 * time.Nanosecond,
			AbsTimeout:     1 * time.Nanosecond,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil)

	expBody := auth.ErrorResponse{
		Code:    21,
		Message: "not available to verify code",
	}

	expBodyStr, _ := json.Marshal(expBody)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusBadRequest).
		CookieNotPresent(cname).
		Body(string(expBodyStr)).
		End()

}

func TestVerifyNoEmailInSession(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	token := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, token)

	sessionData := make(map[string]interface{})

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil)

	notAvailableToVerify := auth.ErrorResponse{
		Code:    21,
		Message: "not available to verify code",
	}
	notAvailableToVerifyStr, _ := json.Marshal(notAvailableToVerify)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusBadRequest).
		Body(string(notAvailableToVerifyStr)).
		Cookie(cname, "").
		End()
}

func TestVerifyBadEmailInSession(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	token := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, token)

	sessionData := make(map[string]interface{})
	sessionData["login"] = 666

	ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil)

	notAvailableToVerify := auth.ErrorResponse{
		Code:    21,
		Message: "not available to verify code",
	}
	notAvailableToVerifyStr, _ := json.Marshal(notAvailableToVerify)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusBadRequest).
		Body(string(notAvailableToVerifyStr)).
		Cookie(cname, "").
		End()
}

func TestVerifyInvalidVerifyRequest(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	sessionData := make(map[string]interface{})
	sessionData["login"] = "123@test.mail"

	badRequestBody := auth.ErrorResponse{
		Code:    2,
		Message: "bad request body",
	}
	badRequestBodyStr, _ := json.Marshal(badRequestBody)

	tt := []struct {
		name             string
		expectedRespBody string
		rqBody           string
	}{
		{"wrong field", string(badRequestBodyStr), `{"wrong_field":"value"}`},
		{"empty body", string(badRequestBodyStr), ``},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			apitest.
				New().
				Handler(router).
				Post("/verify").
				Header("Content-Type", "application/json").
				Cookie(cname, cvalue).
				Body(tc.rqBody).
				Expect(t).
				Status(http.StatusBadRequest).
				Body(tc.expectedRespBody).
				CookieNotPresent(cname).
				End()
		})
	}
}

func TestVerifyInvalidTokenFormat(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	sessionData := make(map[string]interface{})
	sessionData["login"] = "123@test.mail"

	wrongFormatToken := "1234"
	rbody := fmt.Sprintf(`{"token":"%v"}`, wrongFormatToken)

	expResp := auth.ErrorValidationResponse{
		Code:    1,
		Message: "validation failed",
		Details: []auth.ValidationError{
			{"Token", "invalid token id"},
		},
	}
	badRequestBodyStr, _ := json.Marshal(expResp)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusBadRequest).
		Body(string(badRequestBodyStr)).
		CookieNotPresent(cname).
		End()
}

func TestVerifyWrongCode(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	tkn := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, tkn)

	login := "123@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	sessionData := map[string]interface{}{
		"login": map[string]interface{}{
			"login":       login,
			"attempts":    resendAttempt,
			"canresendat": time.Now().Add(resendTimeout),
		},
	}

	ssmockres := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil)

	tsmock.
		EXPECT().
		Verify(gomock.Any(), cvalue, tkn).
		Return(token.ErrTokenVerification).
		After(ssmockres)

	expBody := auth.VerifyResponse{
		Valid:    false,
		CanRetry: true,
	}

	expBodyStr, _ := json.Marshal(expBody)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusOK).
		CookieNotPresent(cname).
		Body(string(expBodyStr)).
		End()
}

func TestVerifyIncativeToken(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	tkn := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, tkn)

	login := "123@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	sessionData := map[string]interface{}{
		"login": map[string]interface{}{
			"login":       login,
			"attempts":    resendAttempt,
			"canresendat": time.Now().Add(resendTimeout),
		},
	}

	ssmockres := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil)

	tsmock.
		EXPECT().
		Verify(gomock.Any(), cvalue, tkn).
		Return(token.ErrTokenInactive).
		After(ssmockres)

	expBody := auth.VerifyResponse{
		Valid:    false,
		CanRetry: false,
	}

	expBodyStr, _ := json.Marshal(expBody)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusOK).
		Cookie(cname, "").
		Body(string(expBodyStr)).
		End()
}

func TestVerifyUnexpectedErr(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	token := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, token)

	login := "123@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	sessionData := map[string]interface{}{
		"login": map[string]interface{}{
			"login":       login,
			"attempts":    resendAttempt,
			"canresendat": time.Now().Add(resendTimeout),
		},
	}

	ssmockres := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil)

	tsmock.
		EXPECT().
		Verify(gomock.Any(), cvalue, token).
		Return(errors.New("unexpected verification error")).
		After(ssmockres)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusInternalServerError).
		CookieNotPresent(cname).
		End()
}

func TestVerifyGetUserErr(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	token := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, token)

	login := "123@test.mail"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	sessionData := map[string]interface{}{
		"login": map[string]interface{}{
			"login":       login,
			"attempts":    resendAttempt,
			"canresendat": time.Now().Add(resendTimeout),
		},
	}

	ssmockres := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil).
		Times(1)

	tsmockvrfres := tsmock.
		EXPECT().
		Verify(gomock.Any(), cvalue, token).
		Return(nil).
		Times(1).
		After(ssmockres)

	umock.
		EXPECT().
		GetUserByKey(login).
		Return(nil, errors.New("error loading user")).
		Times(1).
		After(tsmockvrfres)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusInternalServerError).
		CookieNotPresent(cname).
		End()
}

type testUser struct {
	id string
}

func (u testUser) GetID() string {
	return u.id
}

func TestVerifyCreateUserSesErr(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	token := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, token)

	login := "123@test.mail"
	userid := "5555"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	sessionData := map[string]interface{}{
		"login": map[string]interface{}{
			"login":       login,
			"attempts":    resendAttempt,
			"canresendat": time.Now().Add(resendTimeout),
		},
	}

	ssmockres := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil).
		Times(1)

	tsmockvrfres := tsmock.
		EXPECT().
		Verify(gomock.Any(), cvalue, token).
		Return(nil).
		Times(1).
		After(ssmockres)

	umockres := umock.
		EXPECT().
		GetUserByKey(login).
		Return(testUser{id: userid}, nil).
		Times(1).
		After(tsmockvrfres)

	ssmock.
		EXPECT().
		CreateUserSession(gomock.Any(), userid, cconf, sconf).
		Return(nil, errors.New("error creating session")).
		Times(1).
		After(umockres)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusInternalServerError).
		CookieNotPresent(cname).
		End()
}

func TestVerifySuccess(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	token := "123456"
	rbody := fmt.Sprintf(`{"token":"%v"}`, token)

	login := "123@test.mail"
	userid := "5555"
	resendAttempt := 3
	resendTimeout := 1 * time.Minute

	router, err := auth.NewAuthRouter(
		cname,
		"/login", "/logout", "/verify", "/send",
		ssmock, tsmock, umock,
		cconf, sconf,
		logr.Discard(),
		resendAttempt, resendTimeout)
	assert.Nil(t, err)

	sessionData := map[string]interface{}{
		"login": map[string]interface{}{
			"login":       login,
			"attempts":    resendAttempt,
			"canresendat": time.Now().Add(resendTimeout),
		},
	}

	ssmockres := ssmock.
		EXPECT().
		LoadSession(gomock.Any(), cvalue).
		Return(&session.Session{
			ID:             cvalue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         true,
			Active:         true,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil).
		Times(1)

	tsmockvrfres := tsmock.
		EXPECT().
		Verify(gomock.Any(), cvalue, token).
		Return(nil).
		Times(1).
		After(ssmockres)

	umockres := umock.
		EXPECT().
		GetUserByKey(login).
		Return(testUser{id: userid}, nil).
		Times(1).
		After(tsmockvrfres)

	cNewValue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4N"
	usres := ssmock.
		EXPECT().
		CreateUserSession(gomock.Any(), userid, cconf, sconf).
		Return(&session.Session{
			ID:             cNewValue,
			Data:           sessionData,
			Opts:           cconf,
			Anonym:         false,
			Active:         true,
			UID:            userid,
			IdleTimeout:    10000 * time.Hour,
			AbsTimeout:     10000 * time.Hour,
			CreatedAt:      time.Now(),
			LastAccessedAt: time.Now(),
		}, nil).
		Times(1).
		After(umockres)

	ssmock.
		EXPECT().
		InvalidateSession(gomock.Any(), cvalue).
		After(usres)

	apitest.
		New().
		Handler(router).
		Post("/verify").
		Header("Content-Type", "application/json").
		Cookie(cname, cvalue).
		Body(rbody).
		Expect(t).
		Status(http.StatusOK).
		Cookie(cname, cNewValue).
		End()
}

func TestLogoutNoCookie(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	apitest.
		New().
		Handler(router).
		Get("/logout").
		Header("Content-Type", "application/json").
		Expect(t).
		Status(http.StatusOK).
		CookieNotPresent(cname).
		End()
}

func TestLogout(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"
	cvalue := "A7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	tt := []struct {
		name string
		err  error
	}{
		{"error present", errors.New("Invalidate session error")},
		{"no error present", nil},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ssmock.
				EXPECT().
				InvalidateSession(gomock.Any(), cvalue).
				Return(tc.err)

			apitest.
				New().
				Handler(router).
				Get("/logout").
				Header("Content-Type", "application/json").
				Cookie(cname, cvalue).
				Expect(t).
				Status(http.StatusOK).
				Cookie(cname, "").
				End()
		})
	}
}

func TestLogoutWrongSessionFormat(t *testing.T) {
	ssmock := smocks.NewMockService(gomock.NewController(t))
	tsmock := tmocks.NewMockService(gomock.NewController(t))
	umock := amocks.NewMockAuthUserService(gomock.NewController(t))

	cconf := session.DefaultCookieConf()
	sconf := session.DefaultSessionConf()
	cname := "sid"

	router, err := auth.NewAuthRouter(cname, "/login", "/logout", "/verify", "/send", ssmock, tsmock, umock, cconf, sconf, logr.Discard(), 3, 1*time.Minute)
	assert.Nil(t, err)

	tt := []struct {
		name string
		sid  string
	}{
		{"unexpected in base32 symbol", "!7TF7SGM5WZRW7WMGY7BRJPQOGWGXATZWT35HXPKHRO3DU2J3L4Q"},
		{"wrong length", "!"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			apitest.
				New().
				Handler(router).
				Get("/logout").
				Header("Content-Type", "application/json").
				Cookie(cname, tc.sid).
				Expect(t).
				Status(http.StatusBadRequest).
				Cookie(cname, "").
				End()
		})
	}
}
