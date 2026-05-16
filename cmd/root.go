package cmd

import "github.com/spf13/cobra"

var appVersion = "dev"

var rootCmd = &cobra.Command{
	Use:   "fileshare",
	Short: "FileShare CLI",
	Long:  "FileShare CLI for running the web server and operational commands.",
}

func Execute() error {
	return rootCmd.Execute()
}

func SetVersion(version string) {
	if version != "" {
		appVersion = version
	}
}
