package main

import (
	"github.com/envport-dev/envport/internal/transport/cli"
	"os"
)

func main() { os.Exit(cli.Execute()) }
