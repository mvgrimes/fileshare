package config

import (
	"strings"
	"testing"
)

func TestLoadSuccess(t *testing.T) {
	t.Setenv("SERVER_ADDRESS", "127.0.0.1")
	t.Setenv("SERVER_PORT", "9090")
	t.Setenv("ENVIRONMENT", "test")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("SESSION_TTL_HOURS", "10")
	t.Setenv("SERVER_URL", "https://sharefile.test")
	t.Setenv("DATABASE_URL", "sharefile.test.db")
	t.Setenv("SESSION_SECRET", "session-secret")
	t.Setenv("JWT_SECRET", "jwt-secret")
	t.Setenv("MAILGUN_DOMAIN", "mg.example")
	t.Setenv("MAILGUN_API_KEY", "key-123")
	t.Setenv("MAILGUN_FROM_EMAIL", "noreply@example.com")
	t.Setenv("AWS_REGION", "us-west-2")
	t.Setenv("S3_BUCKET", "uploads-test")
	t.Setenv("S3_FORCE_PATH_STYLE", "true")
	t.Setenv("SHAREFILE_BRANDING", "Company, Inc.")
	t.Setenv("SHAREFILE_FAVICON", "https://assets.example/favicon.ico")
	t.Setenv("SHAREFILE_LOGO", "https://assets.example/logo.svg")
	t.Setenv("SHAREFILE_LOGO_HERO", "https://assets.example/logo-hero.svg")

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
		t.Fatalf("MailgunAPIBaseURL = %q, want %q", cfg.MailgunAPIBaseURL, "https://api.mailgun.net")
	}
	if cfg.MailgunDomain != "mg.example" {
		t.Fatalf("MailgunDomain = %q, want %q", cfg.MailgunDomain, "mg.example")
	}
	if cfg.AWSRegion != "us-west-2" {
		t.Fatalf("AWSRegion = %q, want %q", cfg.AWSRegion, "us-west-2")
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
}

func TestLoadMissingRequiredEnv(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("SESSION_SECRET", "")
	t.Setenv("JWT_SECRET", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want missing required environment variables error")
	}

	msg := err.Error()
	for _, key := range []string{"DATABASE_URL", "SERVER_URL", "SESSION_SECRET", "JWT_SECRET"} {
		if !strings.Contains(msg, key) {
			t.Fatalf("error %q does not contain %q", msg, key)
		}
	}
}

func TestIntEnvOrDefault(t *testing.T) {
	t.Setenv("SERVER_PORT", "not-a-number")
	if got := intEnvOrDefault("SERVER_PORT", 8080); got != 8080 {
		t.Fatalf("intEnvOrDefault invalid = %d, want %d", got, 8080)
	}
}

func TestLoadRejectsInvalidSessionTTL(t *testing.T) {
	t.Setenv("DATABASE_URL", "sharefile.test.db")
	t.Setenv("SERVER_URL", "https://sharefile.test")
	t.Setenv("SESSION_SECRET", "session-secret")
	t.Setenv("JWT_SECRET", "jwt-secret")
	t.Setenv("SESSION_TTL_HOURS", "0")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want invalid session ttl error")
	}
	if !strings.Contains(err.Error(), "SESSION_TTL_HOURS") {
		t.Fatalf("error = %q, want reference to SESSION_TTL_HOURS", err.Error())
	}
}

func TestBoolEnvOrDefault(t *testing.T) {
	t.Setenv("S3_FORCE_PATH_STYLE", "yes")
	if !boolEnvOrDefault("S3_FORCE_PATH_STYLE", false) {
		t.Fatal("boolEnvOrDefault should parse yes as true")
	}
	t.Setenv("S3_FORCE_PATH_STYLE", "no")
	if boolEnvOrDefault("S3_FORCE_PATH_STYLE", true) {
		t.Fatal("boolEnvOrDefault should parse no as false")
	}
	t.Setenv("S3_FORCE_PATH_STYLE", "not-a-bool")
	if !boolEnvOrDefault("S3_FORCE_PATH_STYLE", true) {
		t.Fatal("boolEnvOrDefault should fall back")
	}
}
