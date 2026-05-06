package cmd

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	_ "modernc.org/sqlite"
)

var addUserCmd = &cobra.Command{
	Use:   "add-user",
	Short: "Create or update a user",
	RunE:  runAddUser,
}

var (
	addUserEmail         string
	addUserPassword      string
	addUserRole          string
	addUserFullName      string
	addUserIfMissing     bool
	addUserPasswordStdin bool
)

func init() {
	addUserCmd.Flags().StringVar(&addUserEmail, "email", "", "user email")
	addUserCmd.Flags().StringVar(&addUserPassword, "password", "", "user password")
	addUserCmd.Flags().StringVar(&addUserRole, "role", "", "user role (admin, account_manager, uploader)")
	addUserCmd.Flags().StringVar(&addUserFullName, "full-name", "", "user full name (defaults to email)")
	addUserCmd.Flags().BoolVar(&addUserIfMissing, "if-missing", false, "only create user if it does not already exist")
	addUserCmd.Flags().BoolVar(&addUserPasswordStdin, "password-stdin", false, "read password from stdin")
	rootCmd.AddCommand(addUserCmd)
}

func runAddUser(cmd *cobra.Command, args []string) error {
	dbConn, err := openSQLiteDBFromEnv()
	if err != nil {
		return err
	}
	defer dbConn.Close()

	email := firstNonEmpty(addUserEmail, os.Getenv("FILESHARE_USER_EMAIL"))
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("user email is required via --email or FILESHARE_USER_EMAIL")
	}
	email = strings.TrimSpace(email)

	role := firstNonEmpty(addUserRole, os.Getenv("FILESHARE_USER_ROLE"), "admin")
	roleID, err := roleIDFromName(role)
	if err != nil {
		return err
	}

	password, err := resolvePassword(addUserPasswordStdin, addUserPassword, "FILESHARE_USER_PASSWORD")
	if err != nil {
		return err
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	fullName := strings.TrimSpace(firstNonEmpty(addUserFullName, os.Getenv("FILESHARE_USER_FULL_NAME"), email))

	tx, err := dbConn.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var existingID string
	err = tx.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup user: %w", err)
	}

	if err == sql.ErrNoRows {
		if _, err := tx.Exec(
			"INSERT INTO users (id, email, full_name, password_hash, is_active) VALUES (?, ?, ?, ?, 1)",
			uuid.NewString(),
			email,
			fullName,
			string(passwordHash),
		); err != nil {
			return fmt.Errorf("create user: %w", err)
		}
	} else {
		if addUserIfMissing {
			fmt.Printf("user %s already exists; skipping\n", email)
			return tx.Commit()
		}
		if _, err := tx.Exec(
			"UPDATE users SET full_name = ?, password_hash = ?, is_active = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
			fullName,
			string(passwordHash),
			existingID,
		); err != nil {
			return fmt.Errorf("update user: %w", err)
		}
	}

	if _, err := tx.Exec(
		"INSERT INTO user_roles (user_id, role_id) SELECT u.id, ? FROM users u WHERE u.email = ? ON CONFLICT(user_id, role_id) DO NOTHING",
		roleID,
		email,
	); err != nil {
		return fmt.Errorf("assign role: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	fmt.Printf("user ready: email=%s role=%s\n", email, role)
	return nil
}

func roleIDFromName(role string) (int64, error) {
	trimmed := strings.TrimSpace(role)
	switch trimmed {
	case "admin":
		return 1, nil
	case "account_manager":
		return 2, nil
	case "uploader":
		return 3, nil
	default:
		return 0, fmt.Errorf("invalid role %q; expected admin, account_manager, or uploader", role)
	}
}
