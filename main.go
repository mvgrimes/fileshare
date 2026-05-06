package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"

	"fileshare/cmd"
)

var version = "0.1.0"

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("error loading .env file: ", err)
	}

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
