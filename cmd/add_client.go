package cmd

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	_ "modernc.org/sqlite"
)

var addClientCmd = &cobra.Command{
	Use:   "add-client",
	Short: "Create or update a client",
	RunE:  runAddClient,
}

var (
	addClientEmail         string
	addClientDisplayName   string
	addClientPassword      string
	addClientCanUpload     bool
	addClientCanUploadSet  bool
	addClientIfMissing     bool
	addClientPasswordStdin bool
)

func init() {
	addClientCmd.Flags().StringVar(&addClientEmail, "email", "", "client email")
	addClientCmd.Flags().StringVar(&addClientDisplayName, "display-name", "", "client display name")
	addClientCmd.Flags().StringVar(&addClientPassword, "password", "", "client password (optional)")
	addClientCmd.Flags().BoolVar(&addClientCanUpload, "can-upload", false, "allow client uploads")
	addClientCmd.Flags().BoolVar(&addClientIfMissing, "if-missing", false, "only create client if it does not already exist")
	addClientCmd.Flags().BoolVar(&addClientPasswordStdin, "password-stdin", false, "read password from stdin")
	addClientCmd.Flags().Lookup("can-upload").NoOptDefVal = "true"
	rootCmd.AddCommand(addClientCmd)
}

func runAddClient(cmd *cobra.Command, args []string) error {
	addClientCanUploadSet = cmd.Flags().Changed("can-upload")

	dbConn, err := openSQLiteDBFromEnv()
	if err != nil {
		return err
	}
	defer dbConn.Close()

	email := strings.TrimSpace(firstNonEmpty(addClientEmail, os.Getenv("SHAREFILE_CLIENT_EMAIL")))
	if email == "" {
		return fmt.Errorf("client email is required via --email or SHAREFILE_CLIENT_EMAIL")
	}

	displayName := strings.TrimSpace(firstNonEmpty(addClientDisplayName, os.Getenv("SHAREFILE_CLIENT_DISPLAY_NAME"), email))

	canUpload, hasCanUpload, err := resolveBool(addClientCanUploadSet, addClientCanUpload, "SHAREFILE_CLIENT_CAN_UPLOAD")
	if err != nil {
		return err
	}

	password, hasPassword, err := resolveOptionalPassword(addClientPasswordStdin, addClientPassword, "SHAREFILE_CLIENT_PASSWORD")
	if err != nil {
		return err
	}
	var passwordHash sql.NullString
	if hasPassword {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if hashErr != nil {
			return fmt.Errorf("hash password: %w", hashErr)
		}
		passwordHash = sql.NullString{Valid: true, String: string(hash)}
	}

	tx, err := dbConn.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var existingID string
	err = tx.QueryRow("SELECT id FROM clients WHERE email = ?", email).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup client: %w", err)
	}

	if err == sql.ErrNoRows {
		clientCanUpload := int64(0)
		if canUpload {
			clientCanUpload = 1
		}
		if _, err := tx.Exec(
			"INSERT INTO clients (id, email, display_name, password_hash, can_upload, is_active) VALUES (?, ?, ?, ?, ?, 1)",
			uuid.NewString(),
			email,
			displayName,
			passwordHash,
			clientCanUpload,
		); err != nil {
			return fmt.Errorf("create client: %w", err)
		}
	} else {
		if addClientIfMissing {
			fmt.Printf("client %s already exists; skipping\n", email)
			return tx.Commit()
		}

		if hasPassword && hasCanUpload {
			if _, err := tx.Exec("UPDATE clients SET display_name = ?, password_hash = ?, can_upload = ?, is_active = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?", displayName, passwordHash, boolToInt64(canUpload), existingID); err != nil {
				return fmt.Errorf("update client: %w", err)
			}
		} else if hasPassword {
			if _, err := tx.Exec("UPDATE clients SET display_name = ?, password_hash = ?, is_active = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?", displayName, passwordHash, existingID); err != nil {
				return fmt.Errorf("update client: %w", err)
			}
		} else if hasCanUpload {
			if _, err := tx.Exec("UPDATE clients SET display_name = ?, can_upload = ?, is_active = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?", displayName, boolToInt64(canUpload), existingID); err != nil {
				return fmt.Errorf("update client: %w", err)
			}
		} else {
			if _, err := tx.Exec("UPDATE clients SET display_name = ?, is_active = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?", displayName, existingID); err != nil {
				return fmt.Errorf("update client: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	if hasCanUpload {
		fmt.Printf("client ready: email=%s can_upload=%t\n", email, canUpload)
		return nil
	}
	fmt.Printf("client ready: email=%s\n", email)
	return nil
}

func boolToInt64(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

func resolveBool(flagSet bool, flagValue bool, envKey string) (bool, bool, error) {
	if flagSet {
		return flagValue, true, nil
	}
	value := strings.TrimSpace(os.Getenv(envKey))
	if value == "" {
		return false, false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, false, fmt.Errorf("invalid boolean for %s: %q", envKey, value)
	}
	return parsed, true, nil
}
