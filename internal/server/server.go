package server

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"sharefile/internal/auth"
	"sharefile/internal/config"
)

type Server struct {
	e        *echo.Echo
	cfg      *config.Config
	log      *slog.Logger
	sessions *auth.Manager
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
			return c.Path() == "/auth/session" || c.Path() == "/auth/logout"
		},
	}))
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))

	sessions := auth.NewManager(12 * time.Hour)
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
		if actorType == "" || actorID == "" {
			return c.String(http.StatusBadRequest, "actor_type and actor_id are required")
		}
		if actorType != "user" && actorType != "client" {
			return c.String(http.StatusBadRequest, "actor_type must be user or client")
		}
		token, _, err := sessions.CreateSession(c.Request().Context(), auth.Principal{ActorType: actorType, ActorID: actorID})
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
	admin.Use(auth.RequireAuth(), auth.RequireActorType("user"))
	admin.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "Admin Dashboard",
			"Role":            principal.ActorType,
			"ActorID":         principal.ActorID,
			"ContentTemplate": "dashboard_content",
		})
	})

	return &Server{e: e, cfg: cfg, log: log, sessions: sessions}
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
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ServerAddress, s.cfg.ServerPort)
	s.log.Info("starting server", "address", addr)
	return s.e.Start(addr)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.e.Shutdown(ctx)
}
