package cmd

import (
	"github.com/spf13/cobra"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Run migrations and initialize admin user",
	RunE:  runBootstrap,
}

var bootstrapIfMissing bool

func init() {
	bootstrapCmd.Flags().
		BoolVar(&bootstrapIfMissing, "if-missing", true, "only create bootstrap admin when it does not exist")
	rootCmd.AddCommand(bootstrapCmd)
}

func runBootstrap(cmd *cobra.Command, args []string) error {
	if err := runMigrateUp(cmd, args); err != nil {
		return err
	}

	originalIfMissing := addUserIfMissing
	originalRole := addUserRole
	defer func() {
		addUserIfMissing = originalIfMissing
		addUserRole = originalRole
	}()

	addUserIfMissing = bootstrapIfMissing
	addUserRole = "admin"

	return runAddUser(cmd, args)
}
