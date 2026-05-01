package cmd

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
}

var migrationsDir string

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply pending migrations",
	RunE:  runMigrateUp,
}

var migrateDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Rollback the latest migration",
	RunE:  runMigrateDown,
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show migration status",
	RunE:  runMigrateStatus,
}

func init() {
	migrateCmd.PersistentFlags().StringVar(&migrationsDir, "dir", "migrations", "path to migration files")

	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	rootCmd.AddCommand(migrateCmd)
}

func runMigrateUp(cmd *cobra.Command, args []string) error {
	db, err := openMigrationDB()
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.Up(db, migrationsDir); err != nil {
		return err
	}

	fmt.Println("migrations applied")
	return nil
}

func runMigrateDown(cmd *cobra.Command, args []string) error {
	db, err := openMigrationDB()
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.Down(db, migrationsDir); err != nil {
		return err
	}

	fmt.Println("migration rolled back")
	return nil
}

func runMigrateStatus(cmd *cobra.Command, args []string) error {
	db, err := openMigrationDB()
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.Status(db, migrationsDir); err != nil {
		return err
	}

	return nil
}

func openMigrationDB() (*sql.DB, error) {
	if err := goose.SetDialect("sqlite3"); err != nil {
		return nil, fmt.Errorf("set goose dialect: %w", err)
	}

	databaseURL, err := migrationDatabaseURLFromEnv()
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %q: %w", databaseURL, err)
	}

	return db, nil
}

func migrationDatabaseURLFromEnv() (string, error) {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return "", fmt.Errorf("DATABASE_URL is required")
	}

	if strings.HasPrefix(databaseURL, "libsql://") {
		return "", fmt.Errorf("libsql:// URLs are not supported by goose sqlite driver; use a local sqlite path for migrations")
	}

	if strings.Contains(databaseURL, "://") {
		u, err := url.Parse(databaseURL)
		if err != nil {
			return "", fmt.Errorf("invalid DATABASE_URL %q: %w", databaseURL, err)
		}

		if u.Scheme != "sqlite" {
			return "", fmt.Errorf("unsupported DATABASE_URL scheme %q; expected sqlite path or sqlite:// URL", u.Scheme)
		}

		databaseURL = "file:" + strings.TrimPrefix(databaseURL, "sqlite://")
	}

	if strings.HasPrefix(databaseURL, "file:") {
		return databaseURL, nil
	}

	cleanPath := filepath.Clean(databaseURL)
	if cleanPath == "." {
		return "", fmt.Errorf("invalid DATABASE_URL %q: expected sqlite file path", databaseURL)
	}

	return cleanPath, nil
}
