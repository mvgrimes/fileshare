package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func (s *Server) registerSystemRoutes() {
	s.e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	s.e.GET("/readyz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
	})
}
