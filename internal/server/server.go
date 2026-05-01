package server

import (
	"context"
	"fmt"
	"io"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"sharefile/internal/config"
)

type Server struct {
	e   *echo.Echo
	cfg *config.Config
	log *slog.Logger
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

	t := template.Must(template.ParseGlob("internal/web/templates/*.html"))
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
	e.Use(middleware.CSRF())
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))

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

	user := e.Group("/user")
	user.GET("/dashboard", func(c echo.Context) error {
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "User Dashboard",
			"Role":            "user",
			"ContentTemplate": "dashboard_content",
		})
	})

	client := e.Group("/client")
	client.GET("/dashboard", func(c echo.Context) error {
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "Client Dashboard",
			"Role":            "client",
			"ContentTemplate": "dashboard_content",
		})
	})

	admin := e.Group("/admin")
	admin.GET("/dashboard", func(c echo.Context) error {
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "Admin Dashboard",
			"Role":            "admin",
			"ContentTemplate": "dashboard_content",
		})
	})

	return &Server{e: e, cfg: cfg, log: log}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ServerAddress, s.cfg.ServerPort)
	s.log.Info("starting server", "address", addr)
	return s.e.Start(addr)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.e.Shutdown(ctx)
}
