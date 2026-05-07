package cmd

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func openSQLiteDBFromEnv() (*sql.DB, error) {
	databaseURL, err := migrationDatabaseURLFromEnv()
	if err != nil {
		return nil, err
	}

	dbConn, err := sql.Open("sqlite", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %q: %w", databaseURL, err)
	}

	return dbConn, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func resolvePassword(fromStdin bool, flagValue, envKey string) (string, error) {
	password, hasPassword, err := resolveOptionalPassword(fromStdin, flagValue, envKey)
	if err != nil {
		return "", err
	}
	if !hasPassword {
		return "", fmt.Errorf(
			"password is required via --password, %s, or --password-stdin",
			envKey,
		)
	}
	return password, nil
}

func resolveOptionalPassword(fromStdin bool, flagValue, envKey string) (string, bool, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", false, fmt.Errorf("read password from stdin: %w", err)
		}
		password := strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(password) == "" {
			return "", false, fmt.Errorf("password from stdin is empty")
		}
		return password, true, nil
	}

	password := firstNonEmpty(flagValue, os.Getenv(envKey))
	if password == "" {
		return "", false, nil
	}
	return password, true, nil
}
