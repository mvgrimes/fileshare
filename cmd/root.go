package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "fileshare",
	Short: "FileShare CLI",
	Long:  "FileShare CLI for running the web server and operational commands.",
}

func Execute() error {
	return rootCmd.Execute()
}
