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
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-mcp/internal/probe"
	"github.com/uvamai/meiscope-mcp/internal/server"
	"github.com/uvamai/meiscope-mcp/internal/version"
)

// Environment variables.
const (
	envMaxProbes = "MEISCOPE_MCP_MAX_PROBES_PER_MINUTE"
	envAllow     = "MEISCOPE_MCP_ALLOW"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
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
	prober, err := proberFromEnv(getenv, logger)
	if err != nil {
		// A security setting the user believes is active must never be
		// silently replaced by a default.
		_, _ = fmt.Fprintf(stderr, "configuration: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	if err := server.Run(ctx, server.Config{Version: version.Version, Logger: logger, Prober: prober}); err != nil {
		logger.ErrorContext(ctx, "server stopped", slog.Any("error", err))
		return 1
	}
	return 0
}

// proberFromEnv builds the prober from MEISCOPE_MCP_MAX_PROBES_PER_MINUTE
// (default 30, 1..120) and MEISCOPE_MCP_ALLOW (optional suffixes and CIDRs).
func proberFromEnv(getenv func(string) string, logger *slog.Logger) (*probe.Prober, error) {
	perMinute := probe.DefaultProbesPerMinute
	if v := strings.TrimSpace(getenv(envMaxProbes)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s=%q is not a whole number", envMaxProbes, v)
		}
		perMinute = n
	}
	budget, err := probe.NewBudget(perMinute, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envMaxProbes, err)
	}
	allow, err := probe.ParseAllow(getenv(envAllow))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envAllow, err)
	}
	attrs := []any{slog.Int("probes_per_minute", perMinute)}
	if allow != nil {
		attrs = append(attrs, slog.String("allow", allow.String()))
	}
	logger.Info("probe policy", attrs...)
	return probe.New(probe.Options{Logger: logger, Budget: budget, Allow: allow}), nil
}
