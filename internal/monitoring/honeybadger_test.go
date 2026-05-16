package monitoring

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"fileshare/internal/config"
)

func TestConfigureDisabledOutsideProduction(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	cfg := &config.Config{Environment: "development"}

	enabled := Configure(cfg, log)
	if enabled {
		t.Fatal("Configure() = true, want false")
	}
	if strings.Contains(buf.String(), "missing") {
		t.Fatalf("unexpected warning log: %s", buf.String())
	}
}

func TestConfigureWarnsWhenKeyMissing(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	cfg := &config.Config{Environment: "production"}

	enabled := Configure(cfg, log)
	if enabled {
		t.Fatal("Configure() = true, want false when api key missing")
	}
	if !strings.Contains(buf.String(), "Honeybadger API key is missing") {
		t.Fatalf("log %q does not mention missing api key", buf.String())
	}
}

func TestReportUsesOverriddenReporter(t *testing.T) {
	called := false
	restore := OverrideReporterForTest(func(err error, metadata map[string]any) {
		called = true
		if err == nil || err.Error() != "boom" {
			t.Fatalf("unexpected err: %v", err)
		}
		if metadata["request_id"] != "r-1" {
			t.Fatalf("request_id = %v, want r-1", metadata["request_id"])
		}
	})
	defer restore()

	Report(errors.New("boom"), map[string]any{"request_id": "r-1"})
	if !called {
		t.Fatal("reporter was not called")
	}
}
