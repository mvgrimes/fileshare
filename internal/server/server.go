package server

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"sharefile/internal/auth"
	"sharefile/internal/config"
	"sharefile/internal/db"

	_ "modernc.org/sqlite"
)

type Server struct {
	e         *echo.Echo
	cfg       *config.Config
	log       *slog.Logger
	sessions  *auth.Manager
	magic     *auth.MagicManager
	magicSend auth.MagicSender
}

type TemplateRenderer struct {
	templates *template.Template
}

func (r *TemplateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	viewData, ok := data.(map[string]any)
	if !ok {
		viewData = map[string]any{}
	}
	viewData["Path"] = c.Request().URL.Path
	return r.templates.ExecuteTemplate(w, name, viewData)
}

func New(cfg *config.Config, log *slog.Logger) *Server {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		_ = c.String(http.StatusInternalServerError, "internal server error")
	}

	t := template.Must(loadTemplates())
	e.Renderer = &TemplateRenderer{templates: t}

	e.Use(middleware.RequestID())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:    true,
		LogURI:       true,
		LogMethod:    true,
		LogLatency:   true,
		LogRequestID: true,
		HandleError:  true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			log.Info("http request",
				"request_id", v.RequestID,
				"method", v.Method,
				"uri", v.URI,
				"status", v.Status,
				"latency", v.Latency.String(),
			)
			return nil
		},
	}))

	e.Use(middleware.Recover())
	e.Use(middleware.Secure())
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/auth/session" || c.Path() == "/auth/logout" || c.Path() == "/auth/sso/login" || c.Path() == "/auth/magic/request" || c.Path() == "/auth/magic/verify"
		},
	}))
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))

	sqlDB, err := sql.Open("sqlite", cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	if err := ensureSessionTable(sqlDB); err != nil {
		panic(err)
	}

	sessions := auth.NewManager(db.New(sqlDB), 12*time.Hour)
	magic := auth.NewMagicManager(15*time.Minute, 60*time.Second)
	magicSend := auth.NoopSender{}
	srv := &Server{e: e, cfg: cfg, log: log, sessions: sessions, magic: magic, magicSend: magicSend}
	e.Use(auth.LoadSession(sessions))

	e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	e.GET("/readyz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
	})

	public := e.Group("")
	public.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "home", map[string]any{
			"Title":           "ShareFile",
			"ContentTemplate": "home_content",
		})
	})
	public.POST("/auth/session", func(c echo.Context) error {
		actorType := c.FormValue("actor_type")
		actorID := c.FormValue("actor_id")
		roles := parseRoles(c.FormValue("roles"))
		if actorType == "" || actorID == "" {
			return c.String(http.StatusBadRequest, "actor_type and actor_id are required")
		}
		if actorType != "user" && actorType != "client" {
			return c.String(http.StatusBadRequest, "actor_type must be user or client")
		}
		token, _, err := sessions.CreateSession(c.Request().Context(), auth.Principal{ActorType: actorType, ActorID: actorID, Roles: roles})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		c.SetCookie(&http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   sCookieSecure(cfg.Environment),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int((12 * time.Hour).Seconds()),
		})
		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/logout", func(c echo.Context) error {
		cookie, err := c.Cookie(auth.SessionCookieName)
		if err == nil {
			_ = sessions.RevokeSession(c.Request().Context(), cookie.Value)
		}
		c.SetCookie(&http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   sCookieSecure(cfg.Environment),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/sso/login", func(c echo.Context) error {
		ssoCookie, err := c.Cookie(cfg.SSOCookieName)
		if err != nil || ssoCookie.Value == "" {
			return c.String(http.StatusUnauthorized, "missing sso cookie")
		}

		validator := auth.NewSSOValidator(cfg.JWTSecret, cfg.SSOIssuer, cfg.SSOAudience)
		claims, err := validator.Validate(ssoCookie.Value)
		if err != nil {
			return c.String(http.StatusUnauthorized, "invalid sso token")
		}

		actorID := claims.UserID
		if actorID == "" {
			actorID = claims.Subject
		}

		token, _, err := sessions.CreateSession(c.Request().Context(), auth.Principal{ActorType: "user", ActorID: actorID, Roles: claims.Roles})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to create session")
		}

		c.SetCookie(&http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   sCookieSecure(cfg.Environment),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int((12 * time.Hour).Seconds()),
		})

		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/magic/request", func(c echo.Context) error {
		clientID := c.FormValue("client_id")
		if clientID == "" {
			return c.String(http.StatusBadRequest, "client_id is required")
		}

		token, _, err := magic.Create(c.Request().Context(), clientID)
		if err != nil {
			if err == auth.ErrMagicLinkThrottled {
				return c.String(http.StatusTooManyRequests, "magic link request throttled")
			}
			return c.String(http.StatusInternalServerError, "failed to create magic link")
		}

		if err := srv.magicSend.SendMagicLink(c.Request().Context(), clientID, token); err != nil {
			log.Error("magic link delivery failed", "client_id", clientID, "error", err.Error())
			return c.String(http.StatusBadGateway, "failed to deliver magic link")
		}

		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/magic/verify", func(c echo.Context) error {
		clientID := c.FormValue("client_id")
		token := c.FormValue("token")
		if clientID == "" || token == "" {
			return c.String(http.StatusBadRequest, "client_id and token are required")
		}

		_, err := magic.Consume(c.Request().Context(), clientID, token)
		if err != nil {
			switch err {
			case auth.ErrMagicLinkExpired, auth.ErrMagicLinkConsumed, auth.ErrMagicLinkNotFound:
				return c.String(http.StatusUnauthorized, "invalid or expired magic link")
			default:
				return c.String(http.StatusInternalServerError, "failed to verify magic link")
			}
		}

		sessionToken, _, err := sessions.CreateSession(c.Request().Context(), auth.Principal{ActorType: "client", ActorID: clientID})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		c.SetCookie(&http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   sCookieSecure(cfg.Environment),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int((12 * time.Hour).Seconds()),
		})
		return c.NoContent(http.StatusNoContent)
	})

	user := e.Group("/user")
	user.Use(auth.RequireAuth(), auth.RequireActorType("user"))
	user.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "User Dashboard",
			"Role":            principal.ActorType,
			"ActorID":         principal.ActorID,
			"ContentTemplate": "dashboard_content",
		})
	})
	user.GET("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if !auth.CanUploadFiles(principal) {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.String(http.StatusOK, "uploader access granted")
	})
	user.GET("/clients", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if !auth.CanManageClients(principal) {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.String(http.StatusOK, "account manager access granted")
	})

	client := e.Group("/client")
	client.Use(auth.RequireAuth(), auth.RequireActorType("client"))
	client.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "Client Dashboard",
			"Role":            principal.ActorType,
			"ActorID":         principal.ActorID,
			"ContentTemplate": "dashboard_content",
		})
	})

	admin := e.Group("/admin")
	admin.Use(auth.RequireAuth(), auth.RequireActorType("user"), auth.RequireRole("admin"))
	admin.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "Admin Dashboard",
			"Role":            principal.ActorType,
			"ActorID":         principal.ActorID,
			"ContentTemplate": "dashboard_content",
		})
	})
	admin.GET("/users", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if !auth.CanManageUsers(principal) {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.String(http.StatusOK, "admin access granted")
	})

	return srv
}

func ensureSessionTable(sqlDB *sql.DB) error {
	_, err := sqlDB.Exec(`
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'client')),
  actor_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  ip_address TEXT,
  user_agent TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  revoked_at TEXT
);
`)
	return err
}

func sCookieSecure(environment string) bool {
	return environment != "development"
}

func loadTemplates() (*template.Template, error) {
	patterns := []string{
		"internal/web/templates/*.html",
		"../web/templates/*.html",
		"../../internal/web/templates/*.html",
	}

	for _, pattern := range patterns {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return template.ParseGlob(pattern)
		}
	}

	return nil, fmt.Errorf("no templates found in known locations")
}

func parseRoles(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	roles := make([]string, 0, len(parts))
	for _, p := range parts {
		r := strings.TrimSpace(p)
		if r != "" {
			roles = append(roles, r)
		}
	}
	return roles
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ServerAddress, s.cfg.ServerPort)
	s.log.Info("starting server", "address", addr)
	return s.e.Start(addr)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.e.Shutdown(ctx)
}
