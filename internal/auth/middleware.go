package auth

import (
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"
)

const (
	SessionCookieName = "sharefile_session"
	principalKey      = "principal"
)

func LoadSession(manager *Manager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie(SessionCookieName)
			if err == nil && strings.TrimSpace(cookie.Value) != "" {
				s, loadErr := manager.LoadSession(c.Request().Context(), cookie.Value)
				if loadErr == nil {
					c.Set(principalKey, s.Principal)
				}
			}
			return next(c)
		}
	}
}

func RequireAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, ok := c.Get(principalKey).(Principal); !ok {
				return c.String(http.StatusUnauthorized, "authentication required")
			}
			return next(c)
		}
	}
}

func RequireActorType(actorType string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			principal, ok := c.Get(principalKey).(Principal)
			if !ok {
				return c.String(http.StatusUnauthorized, "authentication required")
			}
			if principal.ActorType != actorType {
				return c.String(http.StatusForbidden, "forbidden")
			}
			return next(c)
		}
	}
}

func RequireRole(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			principal, ok := c.Get(principalKey).(Principal)
			if !ok {
				return c.String(http.StatusUnauthorized, "authentication required")
			}
			if !slices.Contains(principal.Roles, role) {
				return c.String(http.StatusForbidden, "forbidden")
			}
			return next(c)
		}
	}
}

func PrincipalFromContext(c echo.Context) (Principal, bool) {
	p, ok := c.Get(principalKey).(Principal)
	return p, ok
}
