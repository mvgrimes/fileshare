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
	ServerUrl     string
	Environment   string
	LogLevel      string
	SessionTTL    int

	DatabaseURL   string
	SessionSecret string
	JWTSecret     string
	SSOCookieName string
	SSOIssuer     string
	SSOAudience   string

	MailgunAPIBaseURL string
	MailgunDomain     string
	MailgunAPIKey     string
	MailgunFromEmail  string

	AWSRegion          string
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSSessionToken    string
	S3Endpoint         string
	S3Bucket           string
	S3ForcePathStyle   bool

	Branding string
	Favicon  string
	Logo     string
	LogoHero string
}

func Load() (*Config, error) {
	cfg := &Config{
		ServerAddress: envOrDefault("FILESHARE_SERVER_ADDRESS", "0.0.0.0"),
		ServerPort:    intEnvOrDefault("FILESHARE_SERVER_PORT", 8080),
		ServerUrl:     os.Getenv("FILESHARE_SERVER_URL"),
		Environment:   envOrDefault("FILESHARE_ENVIRONMENT", "development"),
		LogLevel:      envOrDefault("FILESHARE_LOG_LEVEL", "info"),
		SessionTTL:    intEnvOrDefault("FILESHARE_SESSION_TTL_HOURS", 12),
		DatabaseURL:   os.Getenv("FILESHARE_DATABASE_URL"),
		SessionSecret: os.Getenv("FILESHARE_SESSION_SECRET"),
		JWTSecret:     os.Getenv("FILESHARE_JWT_SECRET"),
		SSOCookieName: envOrDefault("FILESHARE_SSO_COOKIE_NAME", "sso_jwt"),
		SSOIssuer:     envOrDefault("FILESHARE_SSO_ISSUER", "fileshare-sso"),
		SSOAudience:   envOrDefault("FILESHARE_SSO_AUDIENCE", "fileshare"),
		MailgunAPIBaseURL: envOrDefault(
			"FILESHARE_MAILGUN_API_BASE_URL",
			"https://api.mailgun.net",
		),
		MailgunDomain:      strings.TrimSpace(os.Getenv("FILESHARE_MAILGUN_DOMAIN")),
		MailgunAPIKey:      strings.TrimSpace(os.Getenv("FILESHARE_MAILGUN_API_KEY")),
		MailgunFromEmail:   strings.TrimSpace(os.Getenv("FILESHARE_MAILGUN_FROM_EMAIL")),
		AWSRegion:          envOrDefault("FILESHARE_AWS_REGION", "us-east-1"),
		AWSAccessKeyID:     strings.TrimSpace(os.Getenv("FILESHARE_AWS_ACCESS_KEY_ID")),
		AWSSecretAccessKey: strings.TrimSpace(os.Getenv("FILESHARE_AWS_SECRET_ACCESS_KEY")),
		AWSSessionToken:    strings.TrimSpace(os.Getenv("FILESHARE_AWS_SESSION_TOKEN")),
		S3Endpoint:         strings.TrimSpace(os.Getenv("FILESHARE_S3_ENDPOINT")),
		S3Bucket:           envOrDefault("FILESHARE_S3_BUCKET", "fileshare-uploads"),
		S3ForcePathStyle:   boolEnvOrDefault("FILESHARE_S3_FORCE_PATH_STYLE", false),
		Branding:           envOrDefault("FILESHARE_BRANDING", "FileShare"),
		Favicon:            strings.TrimSpace(os.Getenv("FILESHARE_FAVICON")),
		Logo:               strings.TrimSpace(os.Getenv("FILESHARE_LOGO")),
		LogoHero:           strings.TrimSpace(os.Getenv("FILESHARE_LOGO_HERO")),
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	missing := make([]string, 0, 3)
	if strings.TrimSpace(c.DatabaseURL) == "" {
		missing = append(missing, "FILESHARE_DATABASE_URL")
	}
	if strings.TrimSpace(c.ServerUrl) == "" {
		missing = append(missing, "FILESHARE_SERVER_URL")
	}
	if strings.TrimSpace(c.SessionSecret) == "" {
		missing = append(missing, "FILESHARE_SESSION_SECRET")
	}
	if strings.TrimSpace(c.JWTSecret) == "" {
		missing = append(missing, "FILESHARE_JWT_SECRET")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	if c.SessionTTL <= 0 {
		return fmt.Errorf("FILESHARE_SESSION_TTL_HOURS must be greater than zero")
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

func boolEnvOrDefault(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}
