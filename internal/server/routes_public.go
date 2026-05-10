package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/db"
	"fileshare/internal/mail"

	"github.com/labstack/echo/v4"
)

func (s *Server) registerPublicRoutes(queries *db.Queries, sessionTTL time.Duration) {
	public := s.e.Group("")
	public.GET("/", func(c echo.Context) error {
		branding := brandProductName(s.cfg.Branding)
		showLoginButton := true
		if cookie, err := c.Cookie(auth.SessionCookieName); err == nil {
			if _, sessionErr := s.sessions.LoadSession(
				c.Request().Context(),
				cookie.Value,
			); sessionErr == nil {
				showLoginButton = false
			}
		}
		return c.Render( http.StatusOK, "base", map[string]any{
				"Title":           branding,
				"Subtitle":        branding,
				"ContentTemplate": "home_content",
				"ShowLoginButton": showLoginButton,
			},)
	})
	public.GET("/login", func(c echo.Context) error {
		return c.Render( http.StatusOK, "base", map[string]any{
				"Title":           "Login",
				"Subtitle":        "Sign in with SSO, user password, or client password.",
				"FlashError":      c.QueryParam("error"),
				"FlashSuccess":    c.QueryParam("success"),
				"ContentTemplate": "login_content",
			},)
	})
	public.GET("/request-link", func(c echo.Context) error {
		return c.Render( http.StatusOK, "base", map[string]any{
				"Title":           "Request Magic Link",
				"Subtitle":        "Enter your email address to receive a one-time login token.",
				"FlashError":      c.QueryParam("error"),
				"FlashSuccess":    c.QueryParam("success"),
				"MagicClientID":   c.QueryParam("client_id"),
				"ContentTemplate": "request_link_content",
			},)
	})
	public.GET("/verify-token", func(c echo.Context) error {
		return c.Render( http.StatusOK, "base", map[string]any{
				"Title":           "Verify Token",
				"Subtitle":        "Enter your email address and token to sign in.",
				"FlashError":      c.QueryParam("error"),
				"FlashSuccess":    c.QueryParam("success"),
				"MagicClientID":   c.QueryParam("client_id"),
				"MagicToken":      c.QueryParam("token"),
				"ContentTemplate": "verify_token_content",
			},)
	})
	public.GET("/reset-password/request", func(c echo.Context) error {
		return c.Render( http.StatusOK, "base", map[string]any{
				"Title":           "Reset Password",
				"Subtitle":        "Enter your email and we'll send a reset link.",
				"FlashError":      c.QueryParam("error"),
				"FlashSuccess":    c.QueryParam("success"),
				"Email":           c.QueryParam("email"),
				"ContentTemplate": "password_reset_request_content",
			},)
	})
	public.GET("/reset-password/confirm", func(c echo.Context) error {
		return c.Render( http.StatusOK, "base", map[string]any{
				"Title":           "Set New Password",
				"Subtitle":        "Choose a new password for your account.",
				"FlashError":      c.QueryParam("error"),
				"FlashSuccess":    c.QueryParam("success"),
				"Token":           c.QueryParam("token"),
				"ContentTemplate": "password_reset_confirm_content",
			},)
	})
	public.POST("/auth/session", func(c echo.Context) error {
		if s.cfg.Environment != "test" {
			return c.String(http.StatusForbidden, "forbidden: test-only endpoint")
		}
		actorType := c.FormValue("actor_type")
		actorID := c.FormValue("actor_id")
		roles := parseRoles(c.FormValue("roles"))
		if actorType == "" || actorID == "" {
			return c.String(http.StatusBadRequest, "actor_type and actor_id are required")
		}
		if actorType != "user" && actorType != "client" {
			return c.String(http.StatusBadRequest, "actor_type must be user or client")
		}
		token, _, err := s.sessions.CreateSession(
			c.Request().Context(),
			auth.Principal{ActorType: actorType, ActorID: actorID, Roles: roles},
		)
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		setSessionCookie(c, s.cfg.Environment, token, sessionTTL)
		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/logout", func(c echo.Context) error {
		cookie, err := c.Cookie(auth.SessionCookieName)
		if err == nil {
			if session, loadErr := s.sessions.LoadSession(
				c.Request().Context(),
				cookie.Value,
			); loadErr == nil {
				auditAuthEvent(
					c,
					queries,
					"auth.logout",
					session.Principal.ActorType,
					session.Principal.ActorID,
					"session",
					session.TokenHash,
					map[string]any{"outcome": "success"},
				)
			}
			_ = s.sessions.RevokeSession(c.Request().Context(), cookie.Value)
		}
		c.SetCookie(
			&http.Cookie{
				Name:     auth.SessionCookieName,
				Value:    "",
				Path:     "/",
				HttpOnly: true,
				Secure:   sCookieSecure(s.cfg.Environment),
				SameSite: http.SameSiteLaxMode,
				MaxAge:   -1,
			},
		)
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/login")
		}
		return c.NoContent(http.StatusNoContent)
	})

	public.POST("/auth/sso/login", func(c echo.Context) error {
		ssoCookie, err := c.Cookie(s.cfg.SSOCookieName)
		if err != nil || ssoCookie.Value == "" {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/login?error="+url.QueryEscape("Missing SSO cookie"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.sso.login",
				"",
				"",
				"user",
				"",
				map[string]any{"outcome": "failure", "reason": "missing_cookie"},
			)
			return c.String(http.StatusUnauthorized, "missing sso cookie")
		}
		validator := auth.NewSSOValidator(s.cfg.JWTSecret, s.cfg.SSOIssuer, s.cfg.SSOAudience)
		claims, err := validator.Validate(ssoCookie.Value)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/login?error="+url.QueryEscape("Invalid SSO token"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.sso.login",
				"",
				"",
				"user",
				"",
				map[string]any{"outcome": "failure", "reason": "invalid_token"},
			)
			return c.String(http.StatusUnauthorized, "invalid sso token")
		}
		actorID, err := s.userSync.UpsertFromSSOClaims(c.Request().Context(), claims)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/login?error="+url.QueryEscape("Invalid SSO claims"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.sso.login",
				"",
				"",
				"user",
				"",
				map[string]any{"outcome": "failure", "reason": "invalid_claims"},
			)
			return c.String(http.StatusUnauthorized, "invalid sso token")
		}
		token, _, err := s.sessions.CreateSession(
			c.Request().Context(),
			auth.Principal{ActorType: "user", ActorID: actorID, Roles: claims.Roles},
		)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/login?error="+url.QueryEscape("Unable to create session"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.sso.login",
				"user",
				actorID,
				"user",
				actorID,
				map[string]any{"outcome": "failure", "reason": "session_create_failed"},
			)
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		auditAuthEvent(
			c,
			queries,
			"auth.sso.login",
			"user",
			actorID,
			"user",
			actorID,
			map[string]any{"outcome": "success"},
		)
		setSessionCookie(c, s.cfg.Environment, token, sessionTTL)
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/dashboard")
		}
		return c.NoContent(http.StatusNoContent)
	})

	public.POST("/auth/magic/request", func(c echo.Context) error {
		clientIdentifier := strings.TrimSpace(c.FormValue("client_id"))
		if clientIdentifier == "" {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/request-link?error="+url.QueryEscape("Email address is required"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.magic.request",
				"",
				"",
				"client",
				"",
				map[string]any{"outcome": "failure", "reason": "missing_client_id"},
			)
			return c.String(http.StatusBadRequest, "client_id is required")
		}
		clientID, err := resolvedClientID(queries, c.Request().Context(), clientIdentifier)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/request-link?error="+url.QueryEscape("No active client found for that email"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.magic.request",
				"",
				"",
				"client",
				clientIdentifier,
				map[string]any{"outcome": "failure", "reason": "client_not_found"},
			)
			return c.String(http.StatusUnauthorized, "invalid client")
		}
		token, _, err := s.magic.Create(c.Request().Context(), clientID)
		if err != nil {
			if err == auth.ErrMagicLinkThrottled {
				if isHTMLRequest(c) {
					return c.Redirect(
						http.StatusSeeOther,
						"/request-link?error="+url.QueryEscape("Magic link request throttled"),
					)
				}
				auditAuthEvent(
					c,
					queries,
					"auth.magic.request",
					"",
					"",
					"client",
					clientIdentifier,
					map[string]any{"outcome": "failure", "reason": "throttled"},
				)
				return c.String(http.StatusTooManyRequests, "magic link request throttled")
			}
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/request-link?error="+url.QueryEscape("Unable to create magic link"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.magic.request",
				"",
				"",
				"client",
				clientIdentifier,
				map[string]any{"outcome": "failure", "reason": "create_failed"},
			)
			return c.String(http.StatusInternalServerError, "failed to create magic link")
		}
		if err := s.magicSend.SendMagicLink(
			c.Request().Context(),
			clientIdentifier,
			token,
		); err != nil {
			s.log.Error(
				"magic link delivery failed",
				"client_id",
				clientIdentifier,
				"error",
				err.Error(),
			)
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/request-link?error="+url.QueryEscape("Failed to deliver magic link"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.magic.request",
				"",
				"",
				"client",
				clientIdentifier,
				map[string]any{"outcome": "failure", "reason": "delivery_failed"},
			)
			return c.String(http.StatusBadGateway, "failed to deliver magic link")
		}
		auditAuthEvent(
			c,
			queries,
			"auth.magic.request",
			"",
			"",
			"client",
			clientIdentifier,
			map[string]any{"outcome": "success"},
		)
		if isHTMLRequest(c) {
			return c.Redirect(
				http.StatusSeeOther,
				"/request-link?success="+url.QueryEscape("Magic link sent"),
			)
		}
		return c.NoContent(http.StatusNoContent)
	})

	public.POST("/auth/magic/verify", func(c echo.Context) error {
		clientIdentifier := strings.TrimSpace(c.FormValue("client_id"))
		token := c.FormValue("token")
		if clientIdentifier == "" || token == "" {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/verify-token?error="+url.QueryEscape("Email address and token are required"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.magic.verify",
				"",
				"",
				"client",
				clientIdentifier,
				map[string]any{"outcome": "failure", "reason": "missing_input"},
			)
			return c.String(http.StatusBadRequest, "client_id and token are required")
		}
		clientID, err := resolvedClientID(queries, c.Request().Context(), clientIdentifier)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/verify-token?error="+url.QueryEscape("Invalid or expired magic link"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.magic.verify",
				"",
				"",
				"client",
				clientIdentifier,
				map[string]any{"outcome": "failure", "reason": "client_not_found"},
			)
			return c.String(http.StatusUnauthorized, "invalid or expired magic link")
		}
		_, err = s.magic.Consume(c.Request().Context(), clientID, token)
		if err != nil {
			switch err {
			case auth.ErrMagicLinkExpired, auth.ErrMagicLinkConsumed, auth.ErrMagicLinkNotFound:
				if isHTMLRequest(c) {
					return c.Redirect(
						http.StatusSeeOther,
						"/verify-token?error="+url.QueryEscape("Invalid or expired magic link"),
					)
				}
				auditAuthEvent(
					c,
					queries,
					"auth.magic.verify",
					"",
					"",
					"client",
					clientIdentifier,
					map[string]any{"outcome": "failure", "reason": "invalid_or_expired"},
				)
				return c.String(http.StatusUnauthorized, "invalid or expired magic link")
			default:
				if isHTMLRequest(c) {
					return c.Redirect(
						http.StatusSeeOther,
						"/verify-token?error="+url.QueryEscape("Failed to verify magic link"),
					)
				}
				auditAuthEvent(
					c,
					queries,
					"auth.magic.verify",
					"",
					"",
					"client",
					clientIdentifier,
					map[string]any{"outcome": "failure", "reason": "verify_failed"},
				)
				return c.String(http.StatusInternalServerError, "failed to verify magic link")
			}
		}
		sessionToken, _, err := s.sessions.CreateSession(
			c.Request().Context(),
			auth.Principal{ActorType: "client", ActorID: clientID},
		)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/verify-token?error="+url.QueryEscape("Unable to create session"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.magic.verify",
				"client",
				clientID,
				"client",
				clientID,
				map[string]any{"outcome": "failure", "reason": "session_create_failed"},
			)
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		auditAuthEvent(
			c,
			queries,
			"auth.magic.verify",
			"client",
			clientID,
			"client",
			clientID,
			map[string]any{"outcome": "success"},
		)
		setSessionCookie(c, s.cfg.Environment, sessionToken, sessionTTL)
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/client/dashboard")
		}
		return c.NoContent(http.StatusNoContent)
	})

	public.POST("/auth/password/login", func(c echo.Context) error {
		email := strings.TrimSpace(c.FormValue("email"))
		password := c.FormValue("password")
		actorType := strings.TrimSpace(c.FormValue("actor_type"))
		if actorType == "" {
			resolvedActorType, err := resolvePasswordActorType(
				c.Request().Context(),
				queries,
				email,
			)
			if err != nil {
				if errors.Is(err, errPasswordLoginEmailConflict) {
					if isHTMLRequest(c) {
						return c.Redirect(
							http.StatusSeeOther,
							"/login?error="+url.QueryEscape(
								"Account configuration conflict for email",
							),
						)
					}
					auditAuthEvent(
						c,
						queries,
						"auth.password.login",
						"",
						"",
						"account",
						email,
						map[string]any{"outcome": "failure", "reason": "email_conflict"},
					)
					return c.String(http.StatusConflict, "account email conflict")
				}
				if isHTMLRequest(c) {
					return c.Redirect(
						http.StatusSeeOther,
						"/login?error="+url.QueryEscape("Failed to authenticate"),
					)
				}
				auditAuthEvent(
					c,
					queries,
					"auth.password.login",
					"",
					"",
					"account",
					email,
					map[string]any{"outcome": "failure", "reason": "actor_resolve_failed"},
				)
				return c.String(http.StatusInternalServerError, "failed to resolve account")
			}
			actorType = resolvedActorType
		}
		if actorType == "user" {
			user, roles, err := s.userPwd.Authenticate(c.Request().Context(), email, password)
			if err != nil {
				switch err {
				case auth.ErrUserPasswordDisabled:
					if isHTMLRequest(c) {
						return c.Redirect(
							http.StatusSeeOther,
							"/login?error="+url.QueryEscape("Password auth disabled"),
						)
					}
					auditAuthEvent(
						c,
						queries,
						"auth.password.login",
						"",
						"",
						"user",
						email,
						map[string]any{"outcome": "failure", "reason": "disabled"},
					)
					return c.String(http.StatusForbidden, "password auth disabled")
				case auth.ErrInvalidUserCredentials:
					if isHTMLRequest(c) {
						return c.Redirect(
							http.StatusSeeOther,
							"/login?error="+url.QueryEscape("Invalid credentials"),
						)
					}
					auditAuthEvent(
						c,
						queries,
						"auth.password.login",
						"",
						"",
						"user",
						email,
						map[string]any{"outcome": "failure", "reason": "invalid_credentials"},
					)
					return c.String(http.StatusUnauthorized, "invalid credentials")
				default:
					if isHTMLRequest(c) {
						return c.Redirect(
							http.StatusSeeOther,
							"/login?error="+url.QueryEscape("Failed to authenticate"),
						)
					}
					auditAuthEvent(
						c,
						queries,
						"auth.password.login",
						"",
						"",
						"user",
						email,
						map[string]any{"outcome": "failure", "reason": "auth_failed"},
					)
					return c.String(http.StatusInternalServerError, "failed to authenticate")
				}
			}
			token, _, err := s.sessions.CreateSession(
				c.Request().Context(),
				auth.Principal{ActorType: "user", ActorID: user.ID, Roles: roles},
			)
			if err != nil {
				if isHTMLRequest(c) {
					return c.Redirect(
						http.StatusSeeOther,
						"/login?error="+url.QueryEscape("Unable to create session"),
					)
				}
				auditAuthEvent(
					c,
					queries,
					"auth.password.login",
					"user",
					user.ID,
					"user",
					user.ID,
					map[string]any{"outcome": "failure", "reason": "session_create_failed"},
				)
				return c.String(http.StatusInternalServerError, "failed to create session")
			}
			auditAuthEvent(
				c,
				queries,
				"auth.password.login",
				"user",
				user.ID,
				"user",
				user.ID,
				map[string]any{"outcome": "success"},
			)
			setSessionCookie(c, s.cfg.Environment, token, sessionTTL)
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/dashboard")
			}
			return c.NoContent(http.StatusNoContent)
		}
		if actorType != "client" {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/login?error="+url.QueryEscape("Invalid account type"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.password.login",
				"",
				"",
				"account",
				email,
				map[string]any{"outcome": "failure", "reason": "invalid_actor_type"},
			)
			return c.String(http.StatusBadRequest, "actor_type must be user or client")
		}
		client, err := s.clientPwd.Authenticate(c.Request().Context(), email, password)
		if err != nil {
			switch err {
			case auth.ErrClientPasswordDisabled:
				if isHTMLRequest(c) {
					return c.Redirect(
						http.StatusSeeOther,
						"/login?error="+url.QueryEscape("Password auth disabled"),
					)
				}
				auditAuthEvent(
					c,
					queries,
					"auth.password.login",
					"",
					"",
					"client",
					email,
					map[string]any{"outcome": "failure", "reason": "disabled"},
				)
				return c.String(http.StatusForbidden, "password auth disabled")
			case auth.ErrInvalidClientCredentials:
				if isHTMLRequest(c) {
					return c.Redirect(
						http.StatusSeeOther,
						"/login?error="+url.QueryEscape("Invalid credentials"),
					)
				}
				auditAuthEvent(
					c,
					queries,
					"auth.password.login",
					"",
					"",
					"client",
					email,
					map[string]any{"outcome": "failure", "reason": "invalid_credentials"},
				)
				return c.String(http.StatusUnauthorized, "invalid credentials")
			default:
				if isHTMLRequest(c) {
					return c.Redirect(
						http.StatusSeeOther,
						"/login?error="+url.QueryEscape("Failed to authenticate"),
					)
				}
				auditAuthEvent(
					c,
					queries,
					"auth.password.login",
					"",
					"",
					"client",
					email,
					map[string]any{"outcome": "failure", "reason": "auth_failed"},
				)
				return c.String(http.StatusInternalServerError, "failed to authenticate")
			}
		}
		token, _, err := s.sessions.CreateSession(
			c.Request().Context(),
			auth.Principal{ActorType: "client", ActorID: client.ID},
		)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/login?error="+url.QueryEscape("Unable to create session"),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.password.login",
				"client",
				client.ID,
				"client",
				client.ID,
				map[string]any{"outcome": "failure", "reason": "session_create_failed"},
			)
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		auditAuthEvent(
			c,
			queries,
			"auth.password.login",
			"client",
			client.ID,
			"client",
			client.ID,
			map[string]any{"outcome": "success"},
		)
		setSessionCookie(c, s.cfg.Environment, token, sessionTTL)
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/client/dashboard")
		}
		return c.NoContent(http.StatusNoContent)
	})

	public.POST("/auth/password/reset/request", func(c echo.Context) error {
		email := strings.TrimSpace(c.FormValue("email"))
		if email == "" {
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/reset-password/request?error="+url.QueryEscape("Email is required"),
				)
			}
			return c.String(http.StatusBadRequest, "email is required")
		}
		result, err := s.resetPwd.Request(c.Request().Context(), email)
		if err != nil {
			switch err {
			case auth.ErrPasswordResetDuplicateEmail:
				auditAuthEvent(
					c,
					queries,
					"auth.password.reset.request",
					"",
					"",
					"email",
					email,
					map[string]any{
						"outcome": "failure",
						"reason":  "duplicate_email_across_actor_types",
					},
				)
				s.log.Error("password reset duplicate email across actor types", "email", email)
			case auth.ErrPasswordResetThrottled:
				auditAuthEvent(
					c,
					queries,
					"auth.password.reset.request",
					"",
					"",
					"email",
					email,
					map[string]any{"outcome": "failure", "reason": "throttled"},
				)
			default:
				auditAuthEvent(
					c,
					queries,
					"auth.password.reset.request",
					"",
					"",
					"email",
					email,
					map[string]any{"outcome": "failure", "reason": "request_failed"},
				)
			}
			if isHTMLRequest(c) {
				return c.Redirect(
					http.StatusSeeOther,
					"/reset-password/request?success="+url.QueryEscape(
						"If the account exists, a reset link has been sent",
					),
				)
			}
			return c.NoContent(http.StatusNoContent)
		}

		if result.Created {
			notifyErr := s.notifier.NotifyPasswordReset(
				c.Request().Context(),
				mail.PasswordResetNotification{
					RecipientEmail: result.Email,
					RecipientName:  result.Email,
					ActorType:      result.ActorType,
					Token:          result.Token,
				},
			)
			if notifyErr != nil {
				s.log.Error(
					"password reset notification failed",
					"email",
					result.Email,
					"error",
					notifyErr.Error(),
				)
			}
			auditAuthEvent(
				c,
				queries,
				"auth.password.reset.request",
				result.ActorType,
				result.ActorID,
				"email",
				result.Email,
				map[string]any{"outcome": "success"},
			)
		} else {
			auditAuthEvent(
				c,
				queries,
				"auth.password.reset.request",
				"",
				"",
				"email",
				email,
				map[string]any{"outcome": "ignored", "reason": "account_not_found"},
			)
		}

		if isHTMLRequest(c) {
			return c.Redirect(
				http.StatusSeeOther,
				"/reset-password/request?success="+url.QueryEscape(
					"If the account exists, a reset link has been sent",
				),
			)
		}
		return c.NoContent(http.StatusNoContent)
	})

	public.POST("/auth/password/reset/confirm", func(c echo.Context) error {
		token := strings.TrimSpace(c.FormValue("token"))
		newPassword := c.FormValue("new_password")
		actorType, actorID, err := s.resetPwd.Confirm(c.Request().Context(), token, newPassword)
		if err != nil {
			reason := "confirm_failed"
			status := http.StatusUnauthorized
			switch err {
			case auth.ErrPasswordResetWeakPassword:
				reason = "weak_password"
				status = http.StatusBadRequest
			case auth.ErrPasswordResetNotFound:
				reason = "not_found"
			case auth.ErrPasswordResetExpired:
				reason = "expired"
			case auth.ErrPasswordResetConsumed:
				reason = "consumed"
			case auth.ErrPasswordResetInvalid:
				reason = "invalid_input"
				status = http.StatusBadRequest
			}
			auditAuthEvent(
				c,
				queries,
				"auth.password.reset.confirm",
				actorType,
				actorID,
				"password_reset",
				token,
				map[string]any{"outcome": "failure", "reason": reason},
			)
			if isHTMLRequest(c) {
				if err == auth.ErrPasswordResetWeakPassword {
					return c.Redirect(
						http.StatusSeeOther,
						"/reset-password/confirm?token="+url.QueryEscape(
							token,
						)+"&error="+url.QueryEscape(
							"Password must be at least 12 characters",
						),
					)
				}
				return c.Redirect(
					http.StatusSeeOther,
					"/reset-password/confirm?token="+url.QueryEscape(
						token,
					)+"&error="+url.QueryEscape(
						"Invalid or expired reset token",
					),
				)
			}
			return c.String(status, "invalid or expired reset token")
		}

		auditAuthEvent(
			c,
			queries,
			"auth.password.reset.confirm",
			actorType,
			actorID,
			"password_reset",
			token,
			map[string]any{"outcome": "success"},
		)
		if isHTMLRequest(c) {
			return c.Redirect(
				http.StatusSeeOther,
				"/login?success="+url.QueryEscape("Password reset successful"),
			)
		}
		return c.NoContent(http.StatusNoContent)
	})
}

var errPasswordLoginEmailConflict = errors.New("email belongs to both user and client")

func resolvePasswordActorType(
	ctx context.Context,
	queries *db.Queries,
	email string,
) (string, error) {
	_, userErr := queries.GetUserByEmail(ctx, email)
	userExists := userErr == nil
	if userErr != nil && !errors.Is(userErr, sql.ErrNoRows) {
		return "", userErr
	}

	_, clientErr := queries.GetClientByEmail(ctx, email)
	clientExists := clientErr == nil
	if clientErr != nil && !errors.Is(clientErr, sql.ErrNoRows) {
		return "", clientErr
	}

	switch {
	case userExists && clientExists:
		return "", errPasswordLoginEmailConflict
	case userExists:
		return "user", nil
	default:
		return "client", nil
	}
}

func resolvedClientID(queries *db.Queries, ctx context.Context, identifier string) (string, error) {
	client, err := queries.GetClientByEmail(ctx, identifier)
	if err == nil {
		return client.ID, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	client, err = queries.GetClientByID(ctx, identifier)
	if err == nil {
		return client.ID, nil
	}
	if err == sql.ErrNoRows {
		return "", auth.ErrForbidden
	}
	return "", err
}
