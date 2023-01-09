package auth

import (
	"context"
	"net/http"

	gs "github.com/asstart/go-session"
	"github.com/go-logr/logr"
	"github.com/go-playground/validator/v10"
)

type AuthMW struct {
	CookieName        string
	SessionContextKey string
	SService          gs.Service
	Logger            logr.Logger
	Vld               *validator.Validate

	CtxRqIDKey interface{}
}

func (mw *AuthMW) Auth() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(mw.CookieName)

			if err == http.ErrNoCookie {
				mw.Logger.V(0).Info("authmw attempt to access without cookies", "rquid", r.Context().Value(mw.CtxRqIDKey))
				authFailed(w)
				return
			}

			sid := cookie.Value

			if err := mw.Vld.Var(sid, CstmSessionValidatorKey); err != nil {
				mw.Logger.V(0).Info("authmw session id validation failed", "rquid", r.Context().Value(mw.CtxRqIDKey))
				authFailed(w)
				mw.invalidateCookie(w)
				return
			}

			s, err := mw.SService.LoadSession(r.Context(), sid)

			if err != nil {
				mw.Logger.V(0).Info("authmw LoadSession error", "rquid", r.Context().Value(mw.CtxRqIDKey), "sid", sid)
				authFailed(w)
				mw.invalidateCookie(w) // need it here?
				return
			}

			if s.IsExpired() {
				mw.Logger.V(0).Info("authmw attempt to use expired session", "rquid", r.Context().Value(mw.CtxRqIDKey), "sid", sid)
				authFailed(w)
				mw.invalidateCookie(w)
				return
			}

			if s.Anonym {
				mw.Logger.V(0).Info("authmw attempto to access with anonym session", "rquid", r.Context().Value(mw.CtxRqIDKey), "sid", sid)
				authFailed(w)
				return
			}

			newCtx := context.WithValue(r.Context(), mw.SessionContextKey, *s)

			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}

func authFailed(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
}

func (mw *AuthMW) invalidateCookie(w http.ResponseWriter) {
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     mw.CookieName,
			Value:    "",
			Secure:   false,
			HttpOnly: true,
			MaxAge:   -1,
			Path:     "/",
		},
	)
}
