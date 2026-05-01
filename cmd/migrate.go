package cmd

import (
	"database/sql"
	"fmt"
	"os"
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
		return nil, err
	}

	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	if strings.HasPrefix(databaseURL, "libsql://") {
		return nil, fmt.Errorf("libsql:// URLs are not supported by goose sqlite driver; use a local sqlite path for migrations")
	}

	db, err := sql.Open("sqlite", databaseURL)
	if err != nil {
		return nil, err
	}

	return db, nil
}
