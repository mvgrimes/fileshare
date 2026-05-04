package server

import (
	"database/sql"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"

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
		users, err := queries.ListUsers(c.Request().Context(), db.ListUsersParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load users")
		}
		roles, err := queries.ListRoles(c.Request().Context())
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load roles")
		}
		items := make([]map[string]any, 0, len(users))
		for _, u := range users {
			roleNames, roleErr := queries.ListRoleNamesByUserID(c.Request().Context(), u.ID)
			if roleErr != nil {
				return c.String(http.StatusInternalServerError, "failed to load user roles")
			}
			items = append(items, map[string]any{"ID": u.ID, "Email": u.Email, "FullName": u.FullName, "IsActive": u.IsActive == 1, "RoleNames": strings.Join(roleNames, ", ")})
		}
		auditAuthEvent(c, queries, "admin.users.view", principal.ActorType, principal.ActorID, "user", "", map[string]any{"outcome": "success"})
		return c.Render(http.StatusOK, "admin_users", map[string]any{"Title": "Manage Users", "Subtitle": "Create users, update profile data, and reset passwords.", "ContentTemplate": "admin_users_content", "Users": items, "Roles": roles, "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success")})
	}, auth.RequireCapability(auth.CapabilityManageUsers))
	admin.POST("/users", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageUsers(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		email := strings.TrimSpace(c.FormValue("email"))
		fullName := strings.TrimSpace(c.FormValue("full_name"))
		roleID := strings.TrimSpace(c.FormValue("role_id"))
		if email == "" || fullName == "" || roleID == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/admin/users?error="+url.QueryEscape("email, full_name, and role_id are required"))
			}
			return c.String(http.StatusBadRequest, "email, full_name, and role_id are required")
		}
		roleIDInt, convErr := parseRoleID(roleID)
		if convErr != nil {
			return c.String(http.StatusBadRequest, "invalid role_id")
		}
		isActive := int64(0)
		if c.FormValue("is_active") == "1" {
			isActive = 1
		}
		passwordHash := sql.NullString{}
		newPassword := strings.TrimSpace(c.FormValue("new_password"))
		if newPassword != "" {
			if len(newPassword) < 12 {
				return c.String(http.StatusBadRequest, "password must be at least 12 characters")
			}
			hash, hashErr := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if hashErr != nil {
				return c.String(http.StatusInternalServerError, "failed to hash password")
			}
			passwordHash = sql.NullString{Valid: true, String: string(hash)}
		}
		userID := uuid.NewString()
		if err := queries.CreateUser(c.Request().Context(), db.CreateUserParams{ID: userID, Email: email, FullName: fullName, PasswordHash: passwordHash, IsActive: isActive}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to create user")
		}
		if err := queries.AddUserRole(c.Request().Context(), db.AddUserRoleParams{UserID: userID, RoleID: roleIDInt}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to assign role")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/admin/users?success="+url.QueryEscape("User created"))
		}
		return c.NoContent(http.StatusCreated)
	}, auth.RequireCapability(auth.CapabilityManageUsers))
	admin.POST("/users/:userID", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageUsers(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		userID := c.Param("userID")
		user, err := queries.GetUserByID(c.Request().Context(), userID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "user not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load user")
		}
		fullName := strings.TrimSpace(c.FormValue("full_name"))
		roleID := strings.TrimSpace(c.FormValue("role_id"))
		if fullName == "" || roleID == "" {
			return c.String(http.StatusBadRequest, "full_name and role_id are required")
		}
		roleIDInt, convErr := parseRoleID(roleID)
		if convErr != nil {
			return c.String(http.StatusBadRequest, "invalid role_id")
		}
		isActive := int64(0)
		if c.FormValue("is_active") == "1" {
			isActive = 1
		}
		if err := queries.UpdateUser(c.Request().Context(), db.UpdateUserParams{ID: user.ID, FullName: fullName, PasswordHash: user.PasswordHash, IsActive: isActive}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to update user")
		}
		roles, err := queries.ListUserRoles(c.Request().Context(), user.ID)
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load roles")
		}
		for _, ur := range roles {
			if err := queries.RemoveUserRole(c.Request().Context(), db.RemoveUserRoleParams{UserID: user.ID, RoleID: ur.RoleID}); err != nil {
				return c.String(http.StatusInternalServerError, "failed to clear roles")
			}
		}
		if err := queries.AddUserRole(c.Request().Context(), db.AddUserRoleParams{UserID: user.ID, RoleID: roleIDInt}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to assign role")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/admin/users?success="+url.QueryEscape("User updated"))
		}
		return c.NoContent(http.StatusNoContent)
	}, auth.RequireCapability(auth.CapabilityManageUsers))
	admin.POST("/users/:userID/reset-password", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageUsers(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		userID := c.Param("userID")
		newPassword := strings.TrimSpace(c.FormValue("new_password"))
		if len(newPassword) < 12 {
			return c.String(http.StatusBadRequest, "password must be at least 12 characters")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to hash password")
		}
		if err := queries.UpdateUserPasswordHashByID(c.Request().Context(), userID, sql.NullString{Valid: true, String: string(hash)}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to reset password")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/admin/users?success="+url.QueryEscape("Password reset"))
		}
		return c.NoContent(http.StatusNoContent)
	}, auth.RequireCapability(auth.CapabilityManageUsers))
}

func parseRoleID(roleID string) (int64, error) {
	switch strings.TrimSpace(roleID) {
	case "1":
		return 1, nil
	case "2":
		return 2, nil
	case "3":
		return 3, nil
	default:
		return 0, echo.NewHTTPError(http.StatusBadRequest)
	}
}
