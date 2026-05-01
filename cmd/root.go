package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "sharefile",
	Short: "ShareFile CLI",
	Long:  "ShareFile CLI for running the web server and operational commands.",
}

func Execute() error {
	return rootCmd.Execute()
}
