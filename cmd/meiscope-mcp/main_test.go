package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func TestRunFlags(t *testing.T) {
	tests := []struct {
		args   []string
		env    map[string]string
		code   int
		stdout string
		stderr string
	}{
		{[]string{"-version"}, nil, 0, "meiscope-mcp 0.0.0-dev", ""},
		{[]string{"-no-such-flag"}, nil, 2, "", "flag provided but not defined"},
		{[]string{"-log-level", "loud"}, nil, 2, "", "invalid -log-level"},
		{nil, map[string]string{envMaxProbes: "121"}, 2, "", "between 1 and 120"},
		{nil, map[string]string{envMaxProbes: "lots"}, 2, "", "not a whole number"},
		{nil, map[string]string{envAllow: "*.example.com"}, 2, "", envAllow},
	}
	for _, tc := range tests {
		var out, errb bytes.Buffer
		if code := run(context.Background(), tc.args, env(tc.env), &out, &errb); code != tc.code {
			t.Fatalf("%v %v: code %d, stderr %q", tc.args, tc.env, code, errb.String())
		}
		if !strings.Contains(out.String(), tc.stdout) || !strings.Contains(errb.String(), tc.stderr) {
			t.Fatalf("%v %v: stdout %q stderr %q", tc.args, tc.env, out.String(), errb.String())
		}
	}
}

func TestProberFromEnv(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if _, err := proberFromEnv(env(map[string]string{envMaxProbes: " 120 ", envAllow: "example.internal,10.0.0.0/8"}), logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "probes_per_minute=120") || !strings.Contains(logs.String(), "allow=example.internal,10.0.0.0/8") {
		t.Fatalf("policy not logged: %s", logs.String())
	}
	if _, err := proberFromEnv(env(nil), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("defaults: %v", err)
	}
}
