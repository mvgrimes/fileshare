package logger

import (
	"log/slog"
	"os"
	"strings"

	clog "github.com/charmbracelet/log"
)

func New(level string) *slog.Logger {
	var handler slog.Handler
	if os.Getenv("FILESHARE_ENVIRONMENT") == "development" {
		handler = newDevelopmentLogger(level)
	} else {
		handler = newProductionLogger(level)
	}

	return slog.New(handler)
}

func newProductionLogger(level string) slog.Handler {
	var parsedLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		parsedLevel = slog.LevelDebug
	case "warn":
		parsedLevel = slog.LevelWarn
	case "error":
		parsedLevel = slog.LevelError
	default:
		parsedLevel = slog.LevelInfo
	}

	return slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsedLevel})
}

func newDevelopmentLogger(level string) slog.Handler {
	var parsedLevel clog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		parsedLevel = clog.DebugLevel
	case "warn":
		parsedLevel = clog.WarnLevel
	case "error":
		parsedLevel = clog.ErrorLevel
	default:
		parsedLevel = clog.InfoLevel
	}

	return clog.NewWithOptions(os.Stdout, clog.Options{
		Level: parsedLevel,
	})
}
