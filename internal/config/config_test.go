package config

import (
	"strings"
	"testing"
)

func TestLoadSuccess(t *testing.T) {
	t.Setenv("FILESHARE_SERVER_ADDRESS", "127.0.0.1")
	t.Setenv("FILESHARE_SERVER_PORT", "9090")
	t.Setenv("FILESHARE_ENVIRONMENT", "test")
	t.Setenv("FILESHARE_LOG_LEVEL", "debug")
	t.Setenv("FILESHARE_SESSION_TTL_HOURS", "10")
	t.Setenv("FILESHARE_SERVER_URL", "https://fileshare.test")
	t.Setenv("FILESHARE_DATABASE_URL", "fileshare.test.db")
	t.Setenv("FILESHARE_SESSION_SECRET", "session-secret")
	t.Setenv("FILESHARE_JWT_SECRET", "jwt-secret")
	t.Setenv("FILESHARE_MAILGUN_DOMAIN", "mg.example")
	t.Setenv("FILESHARE_MAILGUN_API_KEY", "key-123")
	t.Setenv("FILESHARE_MAILGUN_FROM_EMAIL", "noreply@example.com")
	t.Setenv("FILESHARE_TEST_ERROR_MONITORING", "true")
	t.Setenv("FILESHARE_HONEYBADGER_API_KEY", "hb-key")
	t.Setenv("FILESHARE_AWS_REGION", "us-west-2")
	t.Setenv("FILESHARE_S3_BUCKET", "uploads-test")
	t.Setenv("FILESHARE_S3_FORCE_PATH_STYLE", "true")
	t.Setenv("FILESHARE_BRANDING", "Company, Inc.")
	t.Setenv("FILESHARE_FAVICON", "https://assets.example/favicon.ico")
	t.Setenv("FILESHARE_LOGO", "https://assets.example/logo.svg")
	t.Setenv("FILESHARE_LOGO_HERO", "https://assets.example/logo-hero.svg")
	t.Setenv("FILESHARE_TURNSTILE_SITE_KEY", "site-key")
	t.Setenv("FILESHARE_TURNSTILE_SECRET_KEY", "secret-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.ServerAddress != "127.0.0.1" {
		t.Fatalf("ServerAddress = %q, want %q", cfg.ServerAddress, "127.0.0.1")
	}
	if cfg.ServerPort != 9090 {
		t.Fatalf("ServerPort = %d, want %d", cfg.ServerPort, 9090)
	}
	if cfg.Environment != "test" {
		t.Fatalf("Environment = %q, want %q", cfg.Environment, "test")
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.SessionTTL != 10 {
		t.Fatalf("SessionTTL = %d, want %d", cfg.SessionTTL, 10)
	}
	if cfg.MailgunAPIBaseURL != "https://api.mailgun.net" {
		t.Fatalf(
			"MailgunAPIBaseURL = %q, want %q",
			cfg.MailgunAPIBaseURL,
			"https://api.mailgun.net",
		)
	}
	if cfg.MailgunDomain != "mg.example" {
		t.Fatalf("MailgunDomain = %q, want %q", cfg.MailgunDomain, "mg.example")
	}
	if cfg.AWSRegion != "us-west-2" {
		t.Fatalf("AWSRegion = %q, want %q", cfg.AWSRegion, "us-west-2")
	}
	if !cfg.TestErrorMonitoring {
		t.Fatal("TestErrorMonitoring = false, want true")
	}
	if cfg.HoneybadgerAPIKey != "hb-key" {
		t.Fatalf("HoneybadgerAPIKey = %q, want %q", cfg.HoneybadgerAPIKey, "hb-key")
	}
	if cfg.S3Bucket != "uploads-test" {
		t.Fatalf("S3Bucket = %q, want %q", cfg.S3Bucket, "uploads-test")
	}
	if !cfg.S3ForcePathStyle {
		t.Fatal("S3ForcePathStyle = false, want true")
	}
	if cfg.Branding != "Company, Inc." {
		t.Fatalf("Branding = %q, want %q", cfg.Branding, "Company, Inc.")
	}
	if cfg.Favicon != "https://assets.example/favicon.ico" {
		t.Fatalf("Favicon = %q, want configured value", cfg.Favicon)
	}
	if cfg.TurnstileSiteKey != "site-key" {
		t.Fatalf("TurnstileSiteKey = %q, want configured value", cfg.TurnstileSiteKey)
	}
	if cfg.TurnstileSecretKey != "secret-key" {
		t.Fatalf("TurnstileSecretKey = %q, want configured value", cfg.TurnstileSecretKey)
	}
}

func TestLoadMissingRequiredEnv(t *testing.T) {
	t.Setenv("FILESHARE_DATABASE_URL", "")
	t.Setenv("FILESHARE_SESSION_SECRET", "")
	t.Setenv("FILESHARE_JWT_SECRET", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want missing required environment variables error")
	}

	msg := err.Error()
	for _, key := range []string{"FILESHARE_DATABASE_URL", "FILESHARE_SERVER_URL", "FILESHARE_SESSION_SECRET", "FILESHARE_JWT_SECRET"} {
		if !strings.Contains(msg, key) {
			t.Fatalf("error %q does not contain %q", msg, key)
		}
	}
}

func TestIntEnvOrDefault(t *testing.T) {
	t.Setenv("FILESHARE_SERVER_PORT", "not-a-number")
	if got := intEnvOrDefault("FILESHARE_SERVER_PORT", 8080); got != 8080 {
		t.Fatalf("intEnvOrDefault invalid = %d, want %d", got, 8080)
	}
}

func TestLoadRejectsInvalidSessionTTL(t *testing.T) {
	t.Setenv("FILESHARE_DATABASE_URL", "fileshare.test.db")
	t.Setenv("FILESHARE_SERVER_URL", "https://fileshare.test")
	t.Setenv("FILESHARE_SESSION_SECRET", "session-secret")
	t.Setenv("FILESHARE_JWT_SECRET", "jwt-secret")
	t.Setenv("FILESHARE_SESSION_TTL_HOURS", "0")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want invalid session ttl error")
	}
	if !strings.Contains(err.Error(), "FILESHARE_SESSION_TTL_HOURS") {
		t.Fatalf("error = %q, want reference to FILESHARE_SESSION_TTL_HOURS", err.Error())
	}
}

func TestBoolEnvOrDefault(t *testing.T) {
	t.Setenv("FILESHARE_S3_FORCE_PATH_STYLE", "yes")
	if !boolEnvOrDefault("FILESHARE_S3_FORCE_PATH_STYLE", false) {
		t.Fatal("boolEnvOrDefault should parse yes as true")
	}
	t.Setenv("FILESHARE_S3_FORCE_PATH_STYLE", "no")
	if boolEnvOrDefault("FILESHARE_S3_FORCE_PATH_STYLE", true) {
		t.Fatal("boolEnvOrDefault should parse no as false")
	}
	t.Setenv("FILESHARE_S3_FORCE_PATH_STYLE", "not-a-bool")
	if !boolEnvOrDefault("FILESHARE_S3_FORCE_PATH_STYLE", true) {
		t.Fatal("boolEnvOrDefault should fall back")
	}
}
