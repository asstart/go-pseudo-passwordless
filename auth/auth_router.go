package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/asstart/go-pseudo-passwordless/auth/token"
	"github.com/asstart/go-session"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-logr/logr"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"github.com/thedevsaddam/renderer"
)

var (
	sessionLoginKey = "login"
)

type ErrorResponse struct {
	Code        int    `json:"code"`
	Message     string `json:"message"`
	Description string `json:"description"`
}

type ErrorValidationResponse struct {
	Code        int               `json:"code"`
	Message     string            `json:"message"`
	Description string            `json:"description"`
	Details     []ValidationError `json:"details"`
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var (
	validationFailedTemplate = ErrorValidationResponse{
		Code:    1,
		Message: "validation failed",
	}
	badRequestBody = ErrorResponse{
		Code:    2,
		Message: "bad request body",
	}
	alreadyLoggedIn = ErrorResponse{
		Code:    11,
		Message: "already logged in",
	}
	loginProcessAlreadyStarted = ErrorResponse{
		Code:    12,
		Message: "login process already started",
	}
	notAvailableToVerify = ErrorResponse{
		Code:    21,
		Message: "not available to verify code",
	}
	resendCodeNoAttempt = ErrorResponse{
		Code:    31,
		Message: "attempts to resend expired",
	}
	resendCodeTimeoutNotExpired = ErrorResponse{
		Code:    32,
		Message: "resend timeout not expired",
	}
	resendCodeNotAvailable = ErrorResponse{
		Code:    33,
		Message: "not available to resend code",
	}
)

type LoginRequest struct {
	Login string `json:"login" validate:"required,email"`
}

const (
	SesKeyLogin string = "login"
)

type ProcessLoginData struct {
	Login       string
	Attempts    int
	CanResendAt time.Time
}

type VerifyRequest struct {
	Token string `json:"token" validate:"required,custom_token_format"`
}

type VerifyResponse struct {
	Valid    bool `json:"valid"`
	CanRetry bool `json:"canRetry,omitempty"`
}

type authRouter struct {
	SessionCookieName string
	SessionContextKey string
	RedirectURL       string
	SService          session.Service
	TService          token.Service
	UService          AuthUserService
	Logger            logr.Logger
	CookieConf        session.CookieConf
	SessionConf       session.Conf

	RetryCodeAttempt int
	RetryTimeout     time.Duration

	CtxRqIDKey interface{}

	vld *validator.Validate
	tr  ut.Translator

	rndr *renderer.Render
}

func NewAuthRouter(
	cookieName string,
	loginURL string, logoutURL, verifyURL string, resendURL string,
	sservice session.Service,
	tservice token.Service,
	aus AuthUserService,
	cc session.CookieConf, sc session.Conf,
	logger logr.Logger,
	resendAttempts int, resendTimeout time.Duration,
) (http.Handler, error) {

	vldtrs, tr, err := RegistrateCustomVldtrs()
	if err != nil {
		return nil, err
	}

	ar := authRouter{
		SessionCookieName: cookieName,
		SessionContextKey: sessionLoginKey,
		SService:          sservice,
		TService:          tservice,
		UService:          aus,
		Logger:            logger.WithName("auth_router"),
		CookieConf:        cc,
		SessionConf:       sc,
		rndr:              renderer.New(),
		vld:               vldtrs,
		tr:                tr,
		RetryCodeAttempt:  resendAttempts,
		RetryTimeout:      resendTimeout,
	}

	r := chi.NewRouter()

	r.Use(middleware.AllowContentType("application/json"))

	r.Post(loginURL, ar.login)
	r.Post(verifyURL, ar.verify)
	r.Get(logoutURL, ar.logout)
	r.Get(resendURL, ar.resend)

	return r, nil
}

func (ar *authRouter) invalidateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     ar.SessionCookieName,
		Value:    "",
		Secure:   false,
		HttpOnly: true,
		MaxAge:   -1,
		Path:     "/",
	})
}

func (ar *authRouter) setCookie(w http.ResponseWriter, s *session.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     ar.SessionCookieName,
		Value:    s.ID,
		Secure:   s.Opts.Secure,
		HttpOnly: s.Opts.HTTPOnly,
		MaxAge:   s.Opts.MaxAge,
		Path:     s.Opts.Path,
		SameSite: http.SameSite(s.Opts.SameSite),
	})
}

func decoder(r io.Reader) *json.Decoder {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	return d
}

func (ar *authRouter) populateErrTmplt(err error) ErrorValidationResponse {
	errs := err.(validator.ValidationErrors)
	ve := []ValidationError{}
	for _, e := range errs {
		ve = append(ve, ValidationError{
			Field:   e.Field(),
			Message: e.Translate(ar.tr),
		})
	}
	validationFailedTemplate.Details = ve
	return validationFailedTemplate
}

func (ar *authRouter) logout(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(ar.SessionCookieName)

	if err != nil {
		ar.rndr.JSON(w, http.StatusOK, renderer.M{})
		return
	}

	if err := ar.vld.Var(ck.Value, CstmSessionValidatorKey); err != nil {
		ar.Logger.V(0).Info("auth.logout session id validation failed", "err", err, "rquid", r.Context().Value(ar.CtxRqIDKey))
		ar.invalidateCookie(w)
		ar.rndr.JSON(w, http.StatusBadRequest, renderer.M{})
		return
	}

	err = ar.SService.InvalidateSession(r.Context(), ck.Value)
	if err != nil {
		ar.Logger.Error(err, "auth.logout session invalidation failed", "err", err, "rquid", r.Context().Value(ar.CtxRqIDKey))
	}

	ar.invalidateCookie(w)
	ar.rndr.JSON(w, http.StatusOK, renderer.M{})
}

func (ar *authRouter) resend(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(ar.SessionCookieName)

	if err == http.ErrNoCookie {
		ar.Logger.V(0).Info("auth.resend attempt to send code again without cookie", "rquid", r.Context().Value(ar.CtxRqIDKey))
		ar.rndr.JSON(w, http.StatusBadRequest, resendCodeNotAvailable)
		return
	}

	sid := ck.Value

	err = ar.vld.Var(sid, CstmSessionValidatorKey)
	if err != nil {
		ar.Logger.V(0).Info("auth.resend session id validation failed", "err", err, "rquid", r.Context().Value(ar.CtxRqIDKey))
		ar.invalidateCookie(w)
		ar.rndr.JSON(w, http.StatusBadRequest, renderer.M{})
		return
	}

	s, err := ar.SService.LoadSession(r.Context(), sid)
	if err != nil {
		ar.Logger.Error(err, "auth.resend LoadSession error", "sid", sid, "rquid", r.Context().Value(ar.CtxRqIDKey))
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	if !s.Anonym || s.IsExpired() {
		ar.Logger.V(0).Info("auth.resend attempt to send code from session in invalid state", "sid", s.ID, "rquid", r.Context().Value(ar.CtxRqIDKey), "anonym", s.Anonym, "expired", s.IsExpired())
		ar.rndr.JSON(w, http.StatusBadRequest, resendCodeNotAvailable)
		return
	}

	var loginProcessData ProcessLoginData
	ok := s.GetStruct(SesKeyLogin, &loginProcessData)
	if !ok {
		ar.Logger.V(0).Info("auth.resend can't get loginProcessData from session", "sid", s.ID, "rquid", r.Context().Value(ar.CtxRqIDKey))
		err := ar.SService.InvalidateSession(r.Context(), s.ID)
		if err != nil {
			ar.Logger.Error(err, "auth.resend session invalidation failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", s.ID)
		}
		ar.invalidateCookie(w)
		ar.rndr.JSON(w, http.StatusBadRequest, resendCodeNotAvailable)
		return
	}

	if loginProcessData.Attempts <= 0 {
		ar.Logger.V(0).Info("auth.resend no attempts left", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", s.ID)
		err := ar.SService.InvalidateSession(r.Context(), s.ID)
		if err != nil {
			ar.Logger.Error(err, "auth.resend session invalidation failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", s.ID)
		}
		ar.invalidateCookie(w)
		ar.rndr.JSON(w, http.StatusBadRequest, resendCodeNoAttempt)
		return
	}

	if time.Now().Before(loginProcessData.CanResendAt) {
		ar.Logger.V(0).Info("auth.resend resend timeout not expired yet", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", s.ID)
		ar.rndr.JSON(w, http.StatusBadRequest, resendCodeTimeoutNotExpired)
		return
	}

	loginProcessData.Attempts--
	loginProcessData.CanResendAt = time.Now().Add(ar.RetryTimeout)

	updS, err := ar.SService.AddAttributes(
		r.Context(),
		s.ID,
		sessionLoginKey, loginProcessData,
	)

	if err != nil {
		ar.Logger.Error(err, "auth.resend error updating session", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", s.ID, "err", err)
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	err = ar.TService.CreateAndDeliver(r.Context(), updS.ID, loginProcessData.Login)
	if err != nil {
		ar.Logger.Error(err, "auth.resend CreateAndDeliver failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", updS.ID, "err", err)
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	ar.rndr.JSON(w, http.StatusOK, renderer.M{})
}

func (ar *authRouter) login(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(ar.SessionCookieName)

	if err != http.ErrNoCookie {

		sid := cookie.Value

		if err := ar.vld.Var(sid, CstmSessionValidatorKey); err != nil {
			ar.Logger.V(0).Info("auth.login session id validation failed", "err", err, "rquid", r.Context().Value(ar.CtxRqIDKey))
			ar.invalidateCookie(w)
			ar.rndr.JSON(w, http.StatusBadRequest, renderer.M{})
			return
		}

		if s, err := ar.SService.LoadSession(r.Context(), sid); err != session.ErrSessionNotFound && err != nil {
			// cookie found, but there're some internal error while loading session
			ar.Logger.Error(err, "auth.login LoadSession failed", "rquid", r.Context().Value(ar.CtxRqIDKey))
			ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
			return
		} else if err == nil && !s.IsExpired() && !s.Anonym {
			// cookie found, not anon session found, user already logged in
			ar.Logger.V(0).Info("auth.login attempt to login from logged user", "rquid", r.Context().Value(ar.CtxRqIDKey), "uid", s.UID, "sid", s.ID)
			ar.rndr.JSON(w, http.StatusBadRequest, alreadyLoggedIn)
			return
		} else if err == nil && !s.IsExpired() && s.Anonym {
			// cookie found, anon session found, login process already started
			// to resend code need to use resend()
			//
			// try to login again
			// will be unavailable until no attempts to resend code left or session not expired
			// need to redesign?
			ar.Logger.V(0).Info("auth.login attempt to initiate login with in process one", "sid", sid, "rquid", r.Context().Value(ar.CtxRqIDKey))
			ar.rndr.JSON(w, http.StatusBadRequest, loginProcessAlreadyStarted)
			return
		}
	}

	var userLogin LoginRequest

	err = decoder(r.Body).Decode(&userLogin)
	if err != nil {
		ar.Logger.V(0).Info("auth.login bad login body", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err)
		ar.rndr.JSON(w, http.StatusBadRequest, badRequestBody)
		return
	}

	err = ar.vld.Struct(userLogin)
	if err != nil {
		ar.Logger.V(0).Info("auth.login login body validation failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err)
		ar.rndr.JSON(w, http.StatusBadRequest, ar.populateErrTmplt(err))
		return
	}

	loginData := ProcessLoginData{
		Login:       userLogin.Login,
		Attempts:    ar.RetryCodeAttempt,
		CanResendAt: time.Now().Add(ar.RetryTimeout),
	}

	as, err := ar.SService.CreateAnonymSession(
		r.Context(),
		ar.CookieConf,
		ar.SessionConf,
		SesKeyLogin, loginData)

	if err != nil {
		ar.Logger.Error(err, "auth.login CreateAnonymSession failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err)
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	err = ar.TService.CreateAndDeliver(r.Context(), as.ID, userLogin.Login)
	if err != nil {
		ar.Logger.Error(err, "auth.login CreateAndDeliver failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err)
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	ar.setCookie(w, as)

	ar.rndr.JSON(w, http.StatusOK, renderer.M{})
}

func (ar *authRouter) verify(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(ar.SessionCookieName)

	if err == http.ErrNoCookie {
		ar.Logger.V(0).Info("auth.verify attempt to verify without session", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err)
		ar.rndr.JSON(w, http.StatusBadRequest, notAvailableToVerify)
		return
	}

	sid := cookie.Value
	if err := ar.vld.Var(sid, CstmSessionValidatorKey); err != nil {
		ar.Logger.V(0).Info("auth.verify sesion id validation failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err)
		ar.invalidateCookie(w)
		ar.rndr.JSON(w, http.StatusBadRequest, renderer.M{})
		return
	}

	var verifyCode VerifyRequest

	err = decoder(r.Body).Decode(&verifyCode)

	if err != nil {
		ar.Logger.V(0).Info("auth.verify bad verify body", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err)
		ar.rndr.JSON(w, http.StatusBadRequest, badRequestBody)
		return
	}

	err = ar.vld.Struct(verifyCode)

	if err != nil {
		ar.Logger.V(0).Info("auth.verify body validation failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err)
		ar.rndr.JSON(w, http.StatusBadRequest, ar.populateErrTmplt(err))
		return
	}

	s, err := ar.SService.LoadSession(r.Context(), sid)

	if err == session.ErrSessionNotFound {
		ar.Logger.V(0).Info("auth.verify LoadSession error, session not found", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err, "sid", sid)
		ar.invalidateCookie(w)
		ar.rndr.JSON(w, http.StatusBadRequest, notAvailableToVerify)
		return
	}

	// think about this case, should be opportunity to input code again, if smth goes wrong on server side
	if err != nil {
		ar.Logger.Error(err, "auth.verify LoadSession error", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	if !s.Anonym {
		ar.Logger.V(0).Info("auth.verify attempt to verify by logged in user", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
		ar.rndr.JSON(w, http.StatusBadRequest, alreadyLoggedIn)
		return
	}

	if s.IsExpired() {
		ar.Logger.V(0).Info("auth.verify attempt to verify on expired session", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
		ar.rndr.JSON(w, http.StatusBadRequest, notAvailableToVerify)
		return
	}

	var loginProcessData ProcessLoginData
	ok := s.GetStruct(SesKeyLogin, &loginProcessData)

	if !ok {
		ar.Logger.V(0).Info("auth.verify login not found in session attributes", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
		ar.invalidateCookie(w)
		ar.rndr.JSON(w, http.StatusBadRequest, notAvailableToVerify)
		return
	}

	err = ar.TService.Verify(r.Context(), s.ID, verifyCode.Token)

	if err == token.ErrTokenVerification {
		ar.Logger.V(0).Info("auth.verify Verify verification failed", "rquid", r.Context().Value(ar.CtxRqIDKey), "err", err, "sid", sid)
		resp := VerifyResponse{
			Valid:    false,
			CanRetry: true,
		}
		ar.rndr.JSON(w, http.StatusOK, resp)
		return
	}

	if err == token.ErrTokenInactive {
		ar.Logger.V(0).Info("auth.verify Verify token is inactive", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
		ar.invalidateCookie(w)
		resp := VerifyResponse{
			Valid:    false,
			CanRetry: false,
		}
		ar.rndr.JSON(w, http.StatusOK, resp)
		return
	}

	if err != nil {
		ar.Logger.Error(err, "auth.verify Verify error", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	usr, err := ar.UService.GetUserByKey(loginProcessData.Login)

	if err != nil {
		ar.Logger.Error(err, "auth.verify GetUserByKey error", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	us, err := ar.SService.CreateUserSession(r.Context(), usr.GetID(), ar.CookieConf, ar.SessionConf)
	if err != nil {
		ar.Logger.Error(err, "auth.verify CreateUserSession error", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
		ar.rndr.JSON(w, http.StatusInternalServerError, renderer.M{})
		return
	}

	err = ar.SService.InvalidateSession(r.Context(), s.ID)
	if err != nil {
		ar.Logger.Error(err, "auth.verify InvalidateSession error", "rquid", r.Context().Value(ar.CtxRqIDKey), "sid", sid)
	}

	ar.setCookie(w, us)

	resp := VerifyResponse{
		Valid: true,
	}

	ar.rndr.JSON(w, http.StatusOK, resp)
}
