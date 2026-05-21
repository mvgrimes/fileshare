package monitoring

import (
	"fmt"
	"log/slog"
	"sync"

	"fileshare/internal/config"

	honeybadger "github.com/honeybadger-io/honeybadger-go"
)

var (
	reportMu sync.RWMutex
	enabled  bool
	reportFn = func(err error, metadata map[string]any) {
		if err == nil {
			return
		}
		extra := map[string]any{}
		for key, value := range metadata {
			extra[key] = value
		}
		_, _ = honeybadger.Notify(err, extra)
	}
)

func Configure(cfg *config.Config, log *slog.Logger) bool {
	reportMu.Lock()
	enabled = false
	reportMu.Unlock()

	enabledEnv := cfg.Environment == "production" || cfg.TestErrorMonitoring
	if !enabledEnv {
		return false
	}

	if cfg.HoneybadgerAPIKey == "" {
		if log != nil {
			log.Warn("error monitoring enabled but Honeybadger API key is missing")
		}
		return false
	}

	honeybadger.Configure(honeybadger.Configuration{
		APIKey: cfg.HoneybadgerAPIKey,
		Env:    cfg.Environment,
	})

	if log != nil {
		log.Info("honeybadger error monitoring enabled")
	}

	reportMu.Lock()
	enabled = true
	reportMu.Unlock()

	return true
}

func Report(err error, metadata map[string]any) {
	reportMu.RLock()
	if !enabled {
		reportMu.RUnlock()
		return
	}
	defer reportMu.RUnlock()
	reportFn(err, metadata)
}

func OverrideReporterForTest(fn func(error, map[string]any)) func() {
	reportMu.Lock()
	previous := reportFn
	previousEnabled := enabled
	enabled = true
	reportFn = func(err error, metadata map[string]any) {
		if fn != nil {
			fn(err, metadata)
		}
	}
	reportMu.Unlock()

	return func() {
		reportMu.Lock()
		reportFn = previous
		enabled = previousEnabled
		reportMu.Unlock()
	}
}

func WrapHTTPError(err error, requestID, method, uri string) error {
	if err == nil {
		return nil
	}
	if method == "" && uri == "" {
		return err
	}
	return fmt.Errorf("%s %s: %w", method, uri, err)
}
