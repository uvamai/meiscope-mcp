// Command meiscope-mcp is an MCP server (stdio) that inspects X.509
// certificates, TLS endpoints and certificate expiry risk.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/uvamai/meiscope-mcp/internal/server"
	"github.com/uvamai/meiscope-mcp/internal/version"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("meiscope-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	logLevel := fs.String("log-level", "info", "log level on stderr: debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		if _, err := fmt.Fprintf(stdout, "meiscope-mcp %s (%s)\n", version.Version, version.Commit); err != nil {
			return 1
		}
		return 0
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid -log-level: %v\n", err)
		return 2
	}
	// stdout carries the MCP protocol; logs go to stderr only.
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	if err := server.Run(ctx, server.Config{Version: version.Version, Logger: logger}); err != nil {
		logger.ErrorContext(ctx, "server stopped", slog.Any("error", err))
		return 1
	}
	return 0
}
