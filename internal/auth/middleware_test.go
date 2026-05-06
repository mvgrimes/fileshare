package auth

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"fileshare/internal/db"

	_ "modernc.org/sqlite"
)

func TestLoadSessionSetsPrincipal(t *testing.T) {
	manager := setupSessionManager(t)
	token, _, err := manager.CreateSession(context.Background(), Principal{ActorType: "user", ActorID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	e := echo.New()
	e.Use(LoadSession(manager))
	e.GET("/", func(c echo.Context) error {
		principal, ok := PrincipalFromContext(c)
		if !ok {
			return c.String(http.StatusUnauthorized, "missing principal")
		}
		return c.String(http.StatusOK, principal.ActorType+":"+principal.ActorID)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "user:user-1" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "user:user-1")
	}
}

func TestLoadSessionIgnoresInvalidSessionToken(t *testing.T) {
	manager := setupSessionManager(t)
	e := echo.New()
	e.Use(LoadSession(manager))
	e.GET("/", func(c echo.Context) error {
		_, ok := PrincipalFromContext(c)
		if ok {
			return c.String(http.StatusInternalServerError, "unexpected principal")
		}
		return c.NoContent(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "invalid-token"})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestRequireCapability(t *testing.T) {
	e := echo.New()
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			role := c.Request().Header.Get("X-Test-Role")
			if role != "" {
				c.Set(principalKey, Principal{ActorType: "user", ActorID: "u-1", Roles: []string{role}})
			}
			return next(c)
		}
	})
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}, RequireCapability(CapabilityManageClients))

	t.Run("allows principal with capability", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		req.Header.Set("X-Test-Role", "account_manager")
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("denies principal without capability", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		req.Header.Set("X-Test-Role", "uploader")
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("requires authentication", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestRequireAuthRedirectsHTMLGetToLogin(t *testing.T) {
	e := echo.New()
	e.GET("/protected", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}, RequireAuth())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get(echo.HeaderLocation); loc != "/login" {
		t.Fatalf("location = %q, want %q", loc, "/login")
	}
}

func TestRequireAuthNonHTMLStillUnauthorized(t *testing.T) {
	e := echo.New()
	e.GET("/protected", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}, RequireAuth())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set(echo.HeaderAccept, "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthEmptyAcceptRedirectsToLogin(t *testing.T) {
	e := echo.New()
	e.GET("/protected", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}, RequireAuth())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get(echo.HeaderLocation); loc != "/login" {
		t.Fatalf("location = %q, want %q", loc, "/login")
	}
}

func setupSessionManager(t *testing.T) *Manager {
	t.Helper()

	sqlDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	_, err = sqlDB.Exec(`
		CREATE TABLE sessions (
		  id TEXT PRIMARY KEY,
		  actor_type TEXT NOT NULL,
		  actor_id TEXT NOT NULL,
		  token_hash TEXT NOT NULL UNIQUE,
		  ip_address TEXT,
		  user_agent TEXT,
		  expires_at TEXT NOT NULL,
		  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		  revoked_at TEXT
		);

		CREATE TABLE roles (
		  id INTEGER PRIMARY KEY,
		  name TEXT NOT NULL UNIQUE
		);

		CREATE TABLE user_roles (
		  user_id TEXT NOT NULL,
		  role_id INTEGER NOT NULL,
		  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		  FOREIGN KEY (role_id) REFERENCES roles(id)
		);
	`)
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	return NewManager(db.New(sqlDB), time.Hour)
}
