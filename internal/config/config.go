package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ServerAddress string
	ServerPort    int
	Environment   string
	LogLevel      string

	DatabaseURL   string
	SessionSecret string
	JWTSecret     string
}

func Load() (*Config, error) {
	cfg := &Config{
		ServerAddress: envOrDefault("SERVER_ADDRESS", "0.0.0.0"),
		ServerPort:    intEnvOrDefault("SERVER_PORT", 8080),
		Environment:   envOrDefault("ENVIRONMENT", "development"),
		LogLevel:      envOrDefault("LOG_LEVEL", "info"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		SessionSecret: os.Getenv("SESSION_SECRET"),
		JWTSecret:     os.Getenv("JWT_SECRET"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	missing := make([]string, 0, 3)
	if strings.TrimSpace(c.DatabaseURL) == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if strings.TrimSpace(c.SessionSecret) == "" {
		missing = append(missing, "SESSION_SECRET")
	}
	if strings.TrimSpace(c.JWTSecret) == "" {
		missing = append(missing, "JWT_SECRET")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return nil
}

func envOrDefault(key, fallback string) string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func intEnvOrDefault(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
