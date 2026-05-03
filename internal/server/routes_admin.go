package server

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"sharefile/internal/auth"
	"sharefile/internal/db"
)

func (s *Server) registerAdminRoutes(queries *db.Queries) {
	admin := s.e.Group("/admin")
	admin.Use(auth.RequireAuth(), auth.RequireActorType("user"), auth.RequireRole("admin"))
	admin.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		return c.Render(http.StatusOK, "dashboard", map[string]any{"Title": "Admin Dashboard", "Role": principal.ActorType, "ActorID": principal.ActorID, "ContentTemplate": "dashboard_content"})
	})
	admin.GET("/users", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageUsers(principal); err != nil {
			auditAuthEvent(c, queries, "admin.users.view", principal.ActorType, principal.ActorID, "user", "", map[string]any{"outcome": "failure", "reason": "forbidden"})
			return c.String(http.StatusForbidden, "forbidden")
		}
		auditAuthEvent(c, queries, "admin.users.view", principal.ActorType, principal.ActorID, "user", "", map[string]any{"outcome": "success"})
		return c.String(http.StatusOK, "admin access granted")
	}, auth.RequireCapability(auth.CapabilityManageUsers))
}
