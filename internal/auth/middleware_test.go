package auth

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"sharefile/internal/db"

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
	`)
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	return NewManager(db.New(sqlDB), time.Hour)
}
