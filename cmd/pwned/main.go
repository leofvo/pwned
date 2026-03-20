package main

import (
	"fmt"
	"io"
	"os"

	"github.com/leofvo/pwned/internal/app"
	"github.com/leofvo/pwned/internal/config"
	"github.com/leofvo/pwned/internal/logging"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}

	logger := logging.New(cfg.LogLevel)
	application := app.New(cfg, logger, stdout, stderr)
	if err := application.Run(args); err != nil {
		logger.Error("command failed", "error", err)
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	return 0
}
