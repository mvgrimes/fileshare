package main

import (
	"fmt"
	"os"

	"fileshare/cmd"

	"github.com/joho/godotenv"
)

var version = "0.1.7"

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("dotenv load: ", err)
	}

	cmd.SetVersion(version)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
