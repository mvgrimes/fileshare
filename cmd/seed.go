package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var seedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Seed development data",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("TODO: implement seed command")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(seedCmd)
}
