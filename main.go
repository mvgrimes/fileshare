package main

import (
	"fmt"
	"os"

	"fileshare/cmd"

	"github.com/joho/godotenv"
)

var version = "0.1.3"

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("error loading .env file: ", err)
	}

	cmd.SetVersion(version)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
