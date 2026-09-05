package main

import (
	"os"

	"github.com/talkdedsec/tlk-huntx/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}
