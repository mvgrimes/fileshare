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
	t.Setenv("DATABASE_URL", "sharefile.test.db")
	t.Setenv("SESSION_SECRET", "session-secret")
	t.Setenv("JWT_SECRET", "jwt-secret")

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
	for _, key := range []string{"DATABASE_URL", "SESSION_SECRET", "JWT_SECRET"} {
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
